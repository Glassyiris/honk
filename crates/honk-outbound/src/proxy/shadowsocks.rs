//! Shadowsocks AEAD outbound handler.
//!
//! Supports the standard AEAD ciphers (legacy, per shadowsocks.org/doc/aead.html):
//! - `aes-128-gcm`
//! - `aes-256-gcm`
//! - `chacha20-ietf-poly1305` (alias `chacha20-poly1305`)
//!
//! and the Shadowsocks 2022 methods (SIP022, implemented in
//! [`super::shadowsocks_2022`]):
//! - `2022-blake3-aes-128-gcm`
//! - `2022-blake3-aes-256-gcm`
//! - `2022-blake3-chacha20-poly1305`
//!
//! The handler dials the Shadowsocks server, performs the salt + subkey
//! handshake, and returns a `ProxyStream` backed by a local duplex pipe.
//! A background task encrypts traffic to the server and decrypts traffic
//! back using Shadowsocks' record chunking (`[len][tag][payload][tag]`).
//!
//! UDP is supported for both cipher families through `dial_udp`: the core
//! exchanges *raw* payload datagrams with the returned socket, while a
//! background bridge task on the other end of a loopback pair performs the
//! Shadowsocks UDP encapsulation (legacy: per-packet salt + AEAD; 2022:
//! session-based separate-header construction) towards the server.
//!
//! References: <https://shadowsocks.org/doc/aead.html>,
//! <https://shadowsocks.org/doc/sip022.html>

use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use hkdf::Hkdf;
use rand::RngCore;
use sha1::Sha1;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use super::shadowsocks_2022::{self, Ss2022Method, Ss2022UdpSession};
use super::{ProxyHandler, ProxyStream, UdpProxySocket};

pub(crate) const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
pub(crate) const CHUNK_MAX_LEN: usize = 0x3FFF; // 2^14 - 1

/// How long the UDP bridge may stay idle before it shuts down. Slightly
/// longer than the core's endpoint reply idle timeout (120s) so the bridge
/// never dies before the core has given up on the endpoint.
const UDP_BRIDGE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Whether `method` names a Shadowsocks 2022 (SIP022) cipher.
pub(crate) fn is_2022_method(method: &str) -> bool {
    matches!(
        method.to_lowercase().as_str(),
        "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305"
    )
}

/// Cipher configuration shared by all supported AEAD methods.
pub(crate) struct CipherConf {
    pub(crate) key_len: usize,
    pub(crate) salt_len: usize,
    pub(crate) nonce_len: usize,
    pub(crate) tag_len: usize,
}

impl CipherConf {
    pub(crate) fn for_method(method: &str) -> anyhow::Result<Self> {
        match method.to_lowercase().as_str() {
            "aes-128-gcm" => Ok(CipherConf {
                key_len: 16,
                salt_len: 16,
                nonce_len: 12,
                tag_len: 16,
            }),
            "aes-256-gcm" => Ok(CipherConf {
                key_len: 32,
                salt_len: 32,
                nonce_len: 12,
                tag_len: 16,
            }),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(CipherConf {
                key_len: 32,
                salt_len: 32,
                nonce_len: 12,
                tag_len: 16,
            }),
            // SIP022: salt length equals the key length.
            "2022-blake3-aes-128-gcm" => Ok(CipherConf {
                key_len: 16,
                salt_len: 16,
                nonce_len: 12,
                tag_len: 16,
            }),
            "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => Ok(CipherConf {
                key_len: 32,
                salt_len: 32,
                nonce_len: 12,
                tag_len: 16,
            }),
            _ => anyhow::bail!("unsupported Shadowsocks cipher: {}", method),
        }
    }
}

/// Owned AEAD cipher enum so we can avoid trait-object gymnastics.
pub(crate) enum AeadCipher {
    Aes128Gcm(Box<aes_gcm::Aes128Gcm>),
    Aes256Gcm(Box<aes_gcm::Aes256Gcm>),
    ChaCha20Poly1305(Box<chacha20poly1305::ChaCha20Poly1305>),
    XChaCha20Poly1305(Box<chacha20poly1305::XChaCha20Poly1305>),
}

impl AeadCipher {
    pub(crate) fn new(method: &str, key: &[u8]) -> anyhow::Result<Self> {
        use aes_gcm::aead::KeyInit;
        match method.to_lowercase().as_str() {
            "aes-128-gcm" | "2022-blake3-aes-128-gcm" => Ok(AeadCipher::Aes128Gcm(Box::new(
                aes_gcm::Aes128Gcm::new_from_slice(key)?,
            ))),
            "aes-256-gcm" | "2022-blake3-aes-256-gcm" => Ok(AeadCipher::Aes256Gcm(Box::new(
                aes_gcm::Aes256Gcm::new_from_slice(key)?,
            ))),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" | "2022-blake3-chacha20-poly1305" => {
                Ok(AeadCipher::ChaCha20Poly1305(Box::new(
                    chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)?,
                )))
            }
            _ => anyhow::bail!("unsupported Shadowsocks cipher: {}", method),
        }
    }

    /// XChaCha20-Poly1305 with a 24-byte nonce, used by the Shadowsocks 2022
    /// chacha UDP construction (keyed directly with the PSK).
    pub(crate) fn new_xchacha20(key: &[u8]) -> anyhow::Result<Self> {
        use aes_gcm::aead::KeyInit;
        Ok(AeadCipher::XChaCha20Poly1305(Box::new(
            chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)?,
        )))
    }

    pub(crate) fn seal(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        use aes_gcm::aead::Aead;
        match self {
            AeadCipher::Aes128Gcm(c) => {
                let nonce: &aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm> =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.encrypt(nonce, plaintext)
            }
            AeadCipher::Aes256Gcm(c) => {
                let nonce: &aes_gcm::aead::Nonce<aes_gcm::Aes256Gcm> =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.encrypt(nonce, plaintext)
            }
            AeadCipher::ChaCha20Poly1305(c) => {
                let nonce: &chacha20poly1305::aead::Nonce<chacha20poly1305::ChaCha20Poly1305> =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.encrypt(nonce, plaintext)
            }
            AeadCipher::XChaCha20Poly1305(c) => {
                let nonce: &chacha20poly1305::XNonce =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.encrypt(nonce, plaintext)
            }
        }
    }

    pub(crate) fn open(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        use aes_gcm::aead::Aead;
        match self {
            AeadCipher::Aes128Gcm(c) => {
                let nonce: &aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm> =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.decrypt(nonce, ciphertext)
            }
            AeadCipher::Aes256Gcm(c) => {
                let nonce: &aes_gcm::aead::Nonce<aes_gcm::Aes256Gcm> =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.decrypt(nonce, ciphertext)
            }
            AeadCipher::ChaCha20Poly1305(c) => {
                let nonce: &chacha20poly1305::aead::Nonce<chacha20poly1305::ChaCha20Poly1305> =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.decrypt(nonce, ciphertext)
            }
            AeadCipher::XChaCha20Poly1305(c) => {
                let nonce: &chacha20poly1305::XNonce =
                    nonce.try_into().map_err(|_| aes_gcm::aead::Error)?;
                c.decrypt(nonce, ciphertext)
            }
        }
    }
}

impl fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AeadCipher::Aes128Gcm(_) => f.write_str("Aes128Gcm"),
            AeadCipher::Aes256Gcm(_) => f.write_str("Aes256Gcm"),
            AeadCipher::ChaCha20Poly1305(_) => f.write_str("ChaCha20Poly1305"),
            AeadCipher::XChaCha20Poly1305(_) => f.write_str("XChaCha20Poly1305"),
        }
    }
}

/// Shadowsocks proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShadowsocksHandler;

impl ShadowsocksHandler {
    pub fn new() -> Self {
        Self
    }

    /// Derive the master key from the password using OpenSSL's EVP_BytesToKey.
    fn master_key(password: &str, key_len: usize) -> Vec<u8> {
        use md5::{Digest, Md5};
        let mut key = Vec::with_capacity(key_len);
        let mut last = Vec::new();
        while key.len() < key_len {
            let mut h = Md5::new();
            h.update(&last);
            h.update(password.as_bytes());
            last = h.finalize().to_vec();
            key.extend_from_slice(&last);
        }
        key.truncate(key_len);
        key
    }

    pub(crate) fn encode_address(target: SocketAddr, target_domain: Option<&str>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(19);
        if let Some(domain) = target_domain {
            buf.push(0x03);
            buf.push(domain.len().min(u8::MAX as usize) as u8);
            buf.extend_from_slice(domain.as_bytes());
        } else {
            match target {
                SocketAddr::V4(v4) => {
                    buf.push(0x01);
                    buf.extend_from_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    buf.push(0x04);
                    buf.extend_from_slice(&v6.ip().octets());
                }
            }
        }
        buf.extend_from_slice(&target.port().to_be_bytes());
        buf
    }

    /// Shared dial tail: connect (or reuse `server`), spawn the appropriate
    /// relay for the cipher family and wrap the client half.
    async fn start_relay(
        &self,
        method: &str,
        password: &str,
        server: TcpStream,
        header: Vec<u8>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> anyhow::Result<ProxyStream> {
        let (client_half, server_half) = tokio::io::duplex(65536);
        if is_2022_method(method) {
            let method_2022 = Ss2022Method::new(method, password)?;
            tokio::spawn(shadowsocks_2022::shadowsocks_2022_relay(
                server,
                server_half,
                method_2022,
                header,
            ));
        } else {
            let conf = CipherConf::for_method(method)?;
            let master_key = Self::master_key(password, conf.key_len);
            tokio::spawn(shadowsocks_relay(
                server,
                server_half,
                method.to_string(),
                master_key,
                header,
            ));
        }
        Ok(ProxyStream {
            stream: Box::new(client_half),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[async_trait]
impl ProxyHandler for ShadowsocksHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::SS
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let method = node.encryption.as_deref().unwrap_or("aes-128-gcm");
        let password = node.password.as_deref().unwrap_or("");
        // Validate the cipher/key material up front so dial fails fast.
        if is_2022_method(method) {
            Ss2022Method::new(method, password)?;
        } else {
            CipherConf::for_method(method)?;
        }

        let addr = format!("{}:{}", node.host(), node.port);
        debug!("Shadowsocks: connecting to {} for target {}", addr, target);
        let server = crate::util::connect_outbound(&addr, connect_timeout).await?;

        let header = Self::encode_address(target, target_domain);
        self.start_relay(method, password, server, header, target, target_domain)
            .await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        server: TcpStream,
        _connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let method = node.encryption.as_deref().unwrap_or("aes-128-gcm");
        let password = node.password.as_deref().unwrap_or("");
        let header = Self::encode_address(target, target_domain);
        self.start_relay(method, password, server, header, target, target_domain)
            .await
    }

    /// UDP relay for both cipher families.
    ///
    /// The core sends/receives raw payload datagrams through the returned
    /// socket (`relay_addr` is a loopback bridge endpoint); the bridge task
    /// performs the Shadowsocks UDP encapsulation towards the server:
    ///
    /// - legacy AEAD: each datagram is `salt | AEAD(subkey)(addr | payload)`
    ///   with a fresh salt and an all-zero nonce;
    /// - 2022: one session per `dial_udp` call (random session id, monotonic
    ///   packet id); AES methods use the separate-header construction, the
    ///   chacha method uses XChaCha20-Poly1305 with a random 24-byte nonce.
    async fn dial_udp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<UdpProxySocket> {
        let method = node.encryption.as_deref().unwrap_or("aes-128-gcm");
        let password = node.password.as_deref().unwrap_or("");
        let socks = Self::encode_address(target, target_domain);

        let crypto = if is_2022_method(method) {
            SsUdpCrypto::V2022(Box::new(Ss2022UdpSession::new(Ss2022Method::new(
                method, password,
            )?)?))
        } else {
            SsUdpCrypto::Legacy(LegacyUdpCrypto::new(method, password)?)
        };

        // Resolve the server address up front: the bridge socket is
        // connected, which also pins the reply peer.
        let lookup = format!("{}:{}", node.host(), node.port);
        let server_addr = tokio::time::timeout(connect_timeout, async {
            let ips = crate::bootstrap::resolve(node.host()).await?;
            ips.into_iter()
                .next()
                .map(|ip| SocketAddr::new(ip, node.port))
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address for host"))
        })
        .await
        .map_err(|_| anyhow::anyhow!("Shadowsocks UDP: resolve {} timed out", lookup))??;

        // Server-facing socket (bypass-marked so eBPF does not re-route it).
        let bind_addr: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
        } else {
            "[::]:0".parse().expect("hardcoded IPv6 bind address")
        };
        let outbound = crate::util::udp_marked_bind(bind_addr).await?;
        outbound.connect(server_addr).await?;
        debug!(
            "Shadowsocks UDP: bridging to {} for target {}",
            server_addr, target
        );

        // Loopback pair: the core talks raw payloads to `front` via
        // `relay_addr` (the address of `back`).
        let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let front_addr = front.local_addr()?;
        let relay_addr = back.local_addr()?;

        tokio::spawn(shadowsocks_udp_bridge(
            back,
            outbound,
            front_addr,
            socks,
            target.port(),
            crypto,
        ));

        Ok(UdpProxySocket {
            socket: Arc::new(front),
            relay_addr,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
            _control: None,
        })
    }

    async fn test_connectivity(&self, node: &Node) -> bool {
        let addr = format!("{}:{}", node.host(), node.port);
        match crate::util::connect_outbound(&addr, std::time::Duration::from_secs(3)).await {
            Ok(_) => true,
            Err(e) => {
                debug!(
                    "Shadowsocks connectivity test failed for {}: {}",
                    node.name, e
                );
                false
            }
        }
    }
}

/// Background relay: encrypt client->server, decrypt server->client.
async fn shadowsocks_relay(
    server: TcpStream,
    client: tokio::io::DuplexStream,
    method: String,
    master_key: Vec<u8>,
    header: Vec<u8>,
) -> anyhow::Result<()> {
    let conf = CipherConf::for_method(&method)?;

    // Split streams so read and write directions are independent.
    let (mut server_read, mut server_write) = server.into_split();
    let (mut client_read, mut client_write) = tokio::io::split(client);

    let mut send_salt = vec![0u8; conf.salt_len];
    rand::rng().fill_bytes(&mut send_salt);
    let mut send_subkey = vec![0u8; conf.key_len];
    hkdf_sha1_derive(&master_key, &send_salt, &mut send_subkey);
    let send_cipher = AeadCipher::new(&method, &send_subkey)?;
    server_write.write_all(&send_salt).await?;

    let mut recv_salt = vec![0u8; conf.salt_len];
    server_read.read_exact(&mut recv_salt).await?;
    let mut recv_subkey = vec![0u8; conf.key_len];
    hkdf_sha1_derive(&master_key, &recv_salt, &mut recv_subkey);
    let recv_cipher = AeadCipher::new(&method, &recv_subkey)?;

    let mut send_nonce = vec![0u8; conf.nonce_len];
    let mut recv_nonce = vec![0u8; conf.nonce_len];

    let c2s = async {
        let mut first = true;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let payload = if first {
                first = false;
                let mut p = Vec::with_capacity(header.len() + n);
                p.extend_from_slice(&header);
                p.extend_from_slice(&buf[..n]);
                p
            } else {
                buf[..n].to_vec()
            };
            write_chunks(&mut server_write, &send_cipher, &mut send_nonce, &payload).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let s2c = async {
        let mut len_buf = vec![0u8; 2 + conf.tag_len];
        loop {
            server_read.read_exact(&mut len_buf).await?;
            let len_plain = recv_cipher
                .open(&recv_nonce, &len_buf)
                .map_err(|e| anyhow::anyhow!("decrypt length failed: {:?}", e))?;
            increment_nonce(&mut recv_nonce);
            let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

            let mut payload = vec![0u8; len + conf.tag_len];
            server_read.read_exact(&mut payload).await?;
            let plain = recv_cipher
                .open(&recv_nonce, &payload)
                .map_err(|e| anyhow::anyhow!("decrypt payload failed: {:?}", e))?;
            increment_nonce(&mut recv_nonce);
            client_write.write_all(&plain).await?;
        }
    };

    tokio::select! {
        r = c2s => r,
        r = s2c => r,
    }
}

/// Encrypt `payload` as Shadowsocks chunks and write them to the server.
pub(crate) async fn write_chunks<W>(
    writer: &mut W,
    cipher: &AeadCipher,
    nonce: &mut [u8],
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + CHUNK_MAX_LEN).min(payload.len());
        let chunk = &payload[offset..end];

        let len = chunk.len() as u16;
        let mut len_plain = vec![0u8; 2];
        len_plain.copy_from_slice(&len.to_be_bytes());
        let len_cipher = cipher
            .seal(nonce, &len_plain)
            .map_err(|e| anyhow::anyhow!("encrypt length failed: {:?}", e))?;
        increment_nonce(nonce);

        let payload_cipher = cipher
            .seal(nonce, chunk)
            .map_err(|e| anyhow::anyhow!("encrypt payload failed: {:?}", e))?;
        increment_nonce(nonce);

        writer.write_all(&len_cipher).await?;
        writer.write_all(&payload_cipher).await?;

        offset = end;
    }
    Ok(())
}

/// Derive a per-session subkey with HKDF-SHA1.
pub(crate) fn hkdf_sha1_derive(master_key: &[u8], salt: &[u8], okm: &mut [u8]) {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    hk.expand(SS_SUBKEY_INFO, okm)
        .expect("valid HKDF output length");
}

/// Increment a nonce treating it as a little-endian counter.
pub(crate) fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        if *byte == 0xFF {
            *byte = 0;
        } else {
            *byte += 1;
            break;
        }
    }
}

/// Length in bytes of the SOCKS5-style address at the start of `buf`.
pub(crate) fn socks_addr_len(buf: &[u8]) -> anyhow::Result<usize> {
    match buf.first() {
        Some(0x01) => {
            if buf.len() < 7 {
                anyhow::bail!("truncated IPv4 socks address");
            }
            Ok(7)
        }
        Some(0x03) => {
            if buf.len() < 2 {
                anyhow::bail!("truncated domain socks address");
            }
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                anyhow::bail!("truncated domain socks address");
            }
            Ok(2 + len + 2)
        }
        Some(0x04) => {
            if buf.len() < 19 {
                anyhow::bail!("truncated IPv6 socks address");
            }
            Ok(19)
        }
        other => anyhow::bail!("invalid socks address type {:?}", other),
    }
}

/// Legacy AEAD UDP encapsulation: `salt | AEAD(subkey)(addr | payload)`
/// with a fresh random salt and an all-zero nonce per datagram.
pub(crate) struct LegacyUdpCrypto {
    method: String,
    master_key: Vec<u8>,
    conf: CipherConf,
}

impl LegacyUdpCrypto {
    pub(crate) fn new(method: &str, password: &str) -> anyhow::Result<Self> {
        let conf = CipherConf::for_method(method)?;
        Ok(Self {
            method: method.to_string(),
            master_key: ShadowsocksHandler::master_key(password, conf.key_len),
            conf,
        })
    }

    pub(crate) fn seal(&self, socks: &[u8], payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut salt = vec![0u8; self.conf.salt_len];
        rand::rng().fill_bytes(&mut salt);
        let mut subkey = vec![0u8; self.conf.key_len];
        hkdf_sha1_derive(&self.master_key, &salt, &mut subkey);
        let cipher = AeadCipher::new(&self.method, &subkey)?;
        let nonce = vec![0u8; self.conf.nonce_len];

        let mut body = Vec::with_capacity(socks.len() + payload.len());
        body.extend_from_slice(socks);
        body.extend_from_slice(payload);
        let sealed = cipher
            .seal(&nonce, &body)
            .map_err(|e| anyhow::anyhow!("seal UDP packet failed: {:?}", e))?;

        let mut out = salt;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub(crate) fn open(&self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        if packet.len() < self.conf.salt_len + self.conf.tag_len {
            anyhow::bail!("UDP packet too short");
        }
        let (salt, ciphertext) = packet.split_at(self.conf.salt_len);
        let mut subkey = vec![0u8; self.conf.key_len];
        hkdf_sha1_derive(&self.master_key, salt, &mut subkey);
        let cipher = AeadCipher::new(&self.method, &subkey)?;
        let nonce = vec![0u8; self.conf.nonce_len];
        let body = cipher
            .open(&nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("open UDP packet failed: {:?}", e))?;
        let skip = socks_addr_len(&body)?;
        Ok(body[skip..].to_vec())
    }
}

/// UDP encapsulation for the two Shadowsocks cipher families.
pub(crate) enum SsUdpCrypto {
    Legacy(LegacyUdpCrypto),
    V2022(Box<Ss2022UdpSession>),
}

impl SsUdpCrypto {
    fn seal(&mut self, socks: &[u8], target_port: u16, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            SsUdpCrypto::Legacy(c) => c.seal(socks, payload),
            SsUdpCrypto::V2022(s) => s.seal_packet(socks, target_port, payload),
        }
    }

    fn open(&mut self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            SsUdpCrypto::Legacy(c) => c.open(packet),
            SsUdpCrypto::V2022(s) => s.open_packet(packet),
        }
    }
}

/// Bridge between the core-facing loopback socket (raw payloads) and the
/// server-facing socket (Shadowsocks UDP encapsulation).
///
/// `back` receives raw payloads from the core and sends decrypted replies
/// back to `front_addr`; `outbound` is connected to the proxy server.
async fn shadowsocks_udp_bridge(
    back: tokio::net::UdpSocket,
    outbound: tokio::net::UdpSocket,
    front_addr: SocketAddr,
    socks: Vec<u8>,
    target_port: u16,
    mut crypto: SsUdpCrypto,
) -> anyhow::Result<()> {
    let mut core_buf = vec![0u8; 65536];
    let mut server_buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            r = back.recv_from(&mut core_buf) => {
                let (n, _src) = r?;
                let packet = crypto.seal(&socks, target_port, &core_buf[..n])?;
                outbound.send(&packet).await?;
            }
            r = outbound.recv(&mut server_buf) => {
                let n = r?;
                match crypto.open(&server_buf[..n]) {
                    Ok(payload) => {
                        back.send_to(&payload, front_addr).await?;
                    }
                    Err(e) => {
                        debug!("Shadowsocks UDP: dropping undecryptable packet: {}", e);
                    }
                }
            }
            _ = tokio::time::sleep(UDP_BRIDGE_IDLE_TIMEOUT) => {
                debug!("Shadowsocks UDP bridge idle timeout, closing");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_evp_bytes_to_key() {
        let key = ShadowsocksHandler::master_key("foobar", 32);
        assert_eq!(key.len(), 32);
        // MD5("foobar") == 3858f62230ac3c915f300c664312c63f, which is the first
        // block of EVP_BytesToKey output.
        assert_eq!(
            &key[..16],
            &[
                0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12,
                0xc6, 0x3f
            ]
        );
    }

    #[test]
    fn test_address_encoding_ipv4() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 80));
        let encoded = ShadowsocksHandler::encode_address(target, None);
        assert_eq!(encoded[0], 0x01);
        assert_eq!(&encoded[1..5], &[93, 184, 216, 34]);
        assert_eq!(&encoded[5..7], &[0x00, 0x50]);
    }

    #[test]
    fn test_address_encoding_domain() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443));
        let encoded = ShadowsocksHandler::encode_address(target, Some("example.com"));
        assert_eq!(encoded[0], 0x03);
        assert_eq!(encoded[1], 11);
        assert_eq!(&encoded[2..13], b"example.com");
        assert_eq!(&encoded[13..15], &[0x01, 0xbb]);
    }

    #[test]
    fn test_nonce_increment() {
        let mut n = [0u8; 12];
        increment_nonce(&mut n);
        assert_eq!(n, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        n[0] = 0xFF;
        increment_nonce(&mut n);
        assert_eq!(n, [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_cipher_conf_lookup() {
        assert!(CipherConf::for_method("aes-128-gcm").is_ok());
        assert!(CipherConf::for_method("AES-256-GCM").is_ok());
        assert!(CipherConf::for_method("chacha20-ietf-poly1305").is_ok());
        assert!(CipherConf::for_method("chacha20-poly1305").is_ok());
        assert!(CipherConf::for_method("2022-blake3-aes-128-gcm").is_ok());
        assert!(CipherConf::for_method("2022-blake3-aes-256-gcm").is_ok());
        assert!(CipherConf::for_method("2022-blake3-chacha20-poly1305").is_ok());
        assert!(CipherConf::for_method("rc4-md5").is_err());
    }

    #[test]
    fn test_is_2022_method() {
        assert!(is_2022_method("2022-blake3-aes-128-gcm"));
        assert!(is_2022_method("2022-BLAKE3-AES-256-GCM"));
        assert!(is_2022_method("2022-blake3-chacha20-poly1305"));
        assert!(!is_2022_method("aes-256-gcm"));
        assert!(!is_2022_method("chacha20-ietf-poly1305"));
    }

    #[test]
    fn test_socks_addr_len() {
        let v4 = ShadowsocksHandler::encode_address(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 53)),
            None,
        );
        assert_eq!(socks_addr_len(&v4).unwrap(), 7);
        let domain = ShadowsocksHandler::encode_address(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)),
            Some("example.com"),
        );
        assert_eq!(socks_addr_len(&domain).unwrap(), 15);
        assert!(socks_addr_len(&[0x05, 1, 2]).is_err());
        assert!(socks_addr_len(&[0x01, 1]).is_err());
    }

    #[test]
    fn test_legacy_udp_roundtrip() {
        let crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
        let socks = ShadowsocksHandler::encode_address(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
            None,
        );
        let payload = b"\xde\xad\xbe\xef dns query";
        let packet = crypto.seal(&socks, payload).unwrap();
        // salt + tag minimum
        assert!(packet.len() > 16 + 16 + payload.len());
        let opened = crypto.open(&packet).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn test_legacy_udp_roundtrip_chacha() {
        let crypto = LegacyUdpCrypto::new("chacha20-ietf-poly1305", "test-password").unwrap();
        let socks = ShadowsocksHandler::encode_address(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443)),
            Some("one.one"),
        );
        let payload = b"quic initial";
        let packet = crypto.seal(&socks, payload).unwrap();
        let opened = crypto.open(&packet).unwrap();
        assert_eq!(opened, payload);
    }

    #[test]
    fn test_legacy_udp_open_rejects_garbage() {
        let crypto = LegacyUdpCrypto::new("aes-256-gcm", "test-password").unwrap();
        assert!(crypto.open(&[0u8; 10]).is_err());
        let mut garbage = vec![0u8; 64];
        rand::rng().fill_bytes(&mut garbage);
        assert!(crypto.open(&garbage).is_err());
    }

    /// End-to-end UDP test: mock legacy-AEAD server, real `dial_udp`,
    /// core-style raw payload exchange through the returned socket.
    #[tokio::test]
    async fn test_dial_udp_legacy_end_to_end() {
        use honk_config::types::NodeProtocol;

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let server_crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                let (n, src) = server.recv_from(&mut buf).await.unwrap();
                let payload = server_crypto.open(&buf[..n]).unwrap();
                let reply: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
                let socks = ShadowsocksHandler::encode_address("8.8.8.8:53".parse().unwrap(), None);
                let packet = server_crypto.seal(&socks, &reply).unwrap();
                server.send_to(&packet, src).await.unwrap();
            }
        });

        let node = Node {
            name: "test-ss-udp".into(),
            protocol: NodeProtocol::SS,
            address: server_addr.ip().to_string(),
            host: String::new(),
            port: server_addr.port(),
            encryption: Some("aes-128-gcm".to_string()),
            password: Some("test-password".to_string()),
            ..Default::default()
        };
        let handler = ShadowsocksHandler::new();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let proxy = handler
            .dial_udp(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();

        proxy
            .socket
            .send_to(b"hello dns", proxy.relay_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 65536];
        let (n, src) = proxy.socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(src, proxy.relay_addr);
        assert_eq!(&buf[..n], b"HELLO DNS");
    }
}
