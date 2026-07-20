//! ShadowsocksR (SSR) outbound handler.
//!
//! SSR extends Shadowsocks with obfuscation plugins and protocol plugins.
//! This handler implements a pragmatic subset:
//!
//! - **AEAD ciphers** (same as SS): aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
//! - **Protocol plugins**: origin (no extra header), auth_sha1_v4
//! - **Obfuscation plugins**: plain (no obfuscation), http_simple (basic)
//!
//! The handler dials the SSR server, optionally sends a protocol header
//! (auth_sha1_v4), then performs the standard SS AEAD handshake (salt +
//! subkey exchange) and relays traffic through a background task.
//!
//! Reference: <https://github.com/shadowsocksrr/shadowsocks-rss/blob/master/doc/protocol.md>

use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use hkdf::Hkdf;
use rand::Rng;
use sha1::Sha1;
use std::fmt;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use super::{ProxyHandler, ProxyStream};

const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";
const CHUNK_MAX_LEN: usize = 0x3FFF; // 2^14 - 1
const AUTH_SHA1_V4_CLIENT_ID_LEN: usize = 4;
const AUTH_SHA1_V4_RESPONSE_LEN: usize = 2;

// Cipher support (same AEAD infrastructure as shadowsocks.rs).

/// Cipher configuration shared by all supported AEAD methods.
struct CipherConf {
    key_len: usize,
    salt_len: usize,
    nonce_len: usize,
    tag_len: usize,
}

impl CipherConf {
    fn for_method(method: &str) -> anyhow::Result<Self> {
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
            _ => anyhow::bail!("unsupported SSR cipher: {}", method),
        }
    }
}

/// Owned AEAD cipher enum so we can avoid trait-object gymnastics.
enum AeadCipher {
    Aes128Gcm(Box<aes_gcm::Aes128Gcm>),
    Aes256Gcm(Box<aes_gcm::Aes256Gcm>),
    ChaCha20Poly1305(Box<chacha20poly1305::ChaCha20Poly1305>),
}

impl AeadCipher {
    fn new(method: &str, key: &[u8]) -> anyhow::Result<Self> {
        use aes_gcm::aead::KeyInit;
        match method.to_lowercase().as_str() {
            "aes-128-gcm" => Ok(AeadCipher::Aes128Gcm(Box::new(
                aes_gcm::Aes128Gcm::new_from_slice(key)?,
            ))),
            "aes-256-gcm" => Ok(AeadCipher::Aes256Gcm(Box::new(
                aes_gcm::Aes256Gcm::new_from_slice(key)?,
            ))),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(AeadCipher::ChaCha20Poly1305(
                Box::new(chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)?),
            )),
            _ => anyhow::bail!("unsupported SSR cipher: {}", method),
        }
    }

    fn seal(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::aead::Error> {
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
        }
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::aead::Error> {
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
        }
    }
}

impl fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AeadCipher::Aes128Gcm(_) => f.write_str("Aes128Gcm"),
            AeadCipher::Aes256Gcm(_) => f.write_str("Aes256Gcm"),
            AeadCipher::ChaCha20Poly1305(_) => f.write_str("ChaCha20Poly1305"),
        }
    }
}

/// Supported SSR protocol plugins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsrProtocol {
    /// No protocol header (plain Shadowsocks).
    Origin,
    /// auth_sha1_v4: HMAC-SHA1-based mutual authentication.
    AuthSha1V4,
}

impl SsrProtocol {
    /// Detect the protocol from the `node.plugin` field (or `node.protocol`
    /// via plugin_opts). Falls back to `Origin` for unknown / empty values.
    fn from_node(node: &Node) -> Self {
        let plugin = node.plugin.as_deref().unwrap_or("").to_lowercase();
        // SSR subscription URLs often carry protocol info in the plugin field.
        if plugin.contains("auth_sha1_v4") || plugin.contains("auth_sha1") {
            return SsrProtocol::AuthSha1V4;
        }
        if plugin.contains("auth_aes128") {
            // auth_aes128_* is not yet implemented; fall back to origin.
            return SsrProtocol::Origin;
        }
        SsrProtocol::Origin
    }
}

/// Supported SSR obfuscation plugins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsrObfs {
    /// No obfuscation.
    Plain,
    /// http_simple: wrap traffic in an HTTP-like header.
    HttpSimple,
}

impl SsrObfs {
    /// Detect the obfuscation from the `node.plugin` field.
    fn from_node(node: &Node) -> Self {
        let plugin = node.plugin.as_deref().unwrap_or("").to_lowercase();
        if plugin.contains("http_simple") {
            return SsrObfs::HttpSimple;
        }
        if plugin.contains("tls1.2_ticket_auth") || plugin.contains("tls1.2") {
            // Not yet implemented; fall back to plain.
            return SsrObfs::Plain;
        }
        SsrObfs::Plain
    }

    /// Parse `node.plugin_opts` for obfs parameters.
    /// Format: `obfs-host=cloudflare.com` or `obfs-host=cloudflare.com;obfs-uri=/`
    fn parse_opts(node: &Node) -> std::collections::HashMap<&str, &str> {
        let mut map = std::collections::HashMap::new();
        let opts = match &node.plugin_opts {
            Some(s) => s.as_str(),
            None => return map,
        };
        for kv in opts.split(';') {
            let kv = kv.trim();
            if let Some((k, v)) = kv.split_once('=') {
                map.insert(k.trim(), v.trim());
            }
        }
        map
    }
}

/// ShadowsocksR proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShadowsocksRHandler;

impl ShadowsocksRHandler {
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

    /// Encode the target address in SOCKS5-style format.
    fn encode_address(target: SocketAddr, target_domain: Option<&str>) -> Vec<u8> {
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

    /// Build the auth_sha1_v4 protocol header.
    ///
    /// Format:
    /// ```text
    /// [client_id: 4 bytes] [hmac: HMAC-SHA1(master_key, client_id || timestamp)] [timestamp: 4 bytes]
    /// ```
    ///
    /// Total length: 4 + 10 (truncated HMAC-SHA1) + 4 = 18 bytes (varies slightly
    /// depending on implementation; the common convention uses the first 10 bytes
    /// of the HMAC-SHA1 output).
    fn build_auth_sha1_v4_header(master_key: &[u8]) -> Vec<u8> {
        let client_id: [u8; AUTH_SHA1_V4_CLIENT_ID_LEN] = rand::random();

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&client_id);
        data.extend_from_slice(&ts.to_be_bytes());

        // HMAC-SHA1(master_key, client_id || timestamp), truncated to 10 bytes.
        let hmac_result = hmac_sha1(master_key, &data);
        let hmac_truncated = &hmac_result[..10];

        let mut header = Vec::with_capacity(18);
        header.extend_from_slice(&client_id);
        header.extend_from_slice(hmac_truncated);
        header.extend_from_slice(&ts.to_be_bytes());
        header
    }

    /// Build the http_simple obfuscation header.
    ///
    /// http_simple wraps the raw TCP stream in a GET request so it looks like
    /// normal web traffic to naive DPI. The server strips this header before
    /// processing the actual SSR data.
    fn build_http_simple_header(
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> Vec<u8> {
        let opts = SsrObfs::parse_opts(node);
        let host = opts.get("obfs-host").copied().unwrap_or("cloudflare.com");
        let uri = opts.get("obfs-uri").copied().unwrap_or("/");
        let _port_part = if target.port() == 80 {
            String::new()
        } else {
            format!(":{}", target.port())
        };
        let _target_host = target_domain
            .map(|d| d.to_string())
            .unwrap_or_else(|| target.ip().to_string());

        // Use the configured obfs-host as the Host header value.
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.100.0\r\nAccept: */*\r\n\r\n",
            uri, host
        )
        .into_bytes()
    }
}

#[async_trait]
impl ProxyHandler for ShadowsocksRHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::SSR
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let method = node.encryption.as_deref().unwrap_or("aes-128-gcm");
        let conf = CipherConf::for_method(method)?;
        let password = node.password.as_deref().unwrap_or("");
        let master_key = Self::master_key(password, conf.key_len);
        let proto = SsrProtocol::from_node(node);
        let obfs = SsrObfs::from_node(node);

        let addr = format!("{}:{}", node.host(), node.port);
        debug!(
            "SSR: connecting to {} for target {} (proto={:?}, obfs={:?})",
            addr, target, proto, obfs
        );
        let server = crate::util::connect_outbound(&addr, connect_timeout).await?;

        let header = Self::encode_address(target, target_domain);
        let (client_half, server_half) = tokio::io::duplex(65536);

        tokio::spawn(ssr_relay(
            server,
            server_half,
            method.to_string(),
            master_key,
            header,
            proto,
            obfs,
            node.clone(),
            target,
            target_domain.map(|s| s.to_string()),
        ));

        Ok(ProxyStream {
            stream: Box::new(client_half),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
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
        let conf = CipherConf::for_method(method)?;
        let master_key = Self::master_key(password, conf.key_len);
        let proto = SsrProtocol::from_node(node);
        let obfs = SsrObfs::from_node(node);

        let header = Self::encode_address(target, target_domain);
        let (client_half, server_half) = tokio::io::duplex(65536);

        tokio::spawn(ssr_relay(
            server,
            server_half,
            method.to_string(),
            master_key,
            header,
            proto,
            obfs,
            node.clone(),
            target,
            target_domain.map(|s| s.to_string()),
        ));

        Ok(ProxyStream {
            stream: Box::new(client_half),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    async fn test_connectivity(&self, node: &Node) -> bool {
        let addr = format!("{}:{}", node.host(), node.port);
        match crate::util::connect_outbound(&addr, std::time::Duration::from_secs(3)).await {
            Ok(_) => true,
            Err(e) => {
                debug!("SSR connectivity test failed for {}: {}", node.name, e);
                false
            }
        }
    }
}

/// Background relay for SSR: optional SSR protocol header → obfs hello →
/// SS AEAD handshake → bidirectional relay.
#[allow(clippy::too_many_arguments)]
async fn ssr_relay(
    server: TcpStream,
    client: tokio::io::DuplexStream,
    method: String,
    master_key: Vec<u8>,
    header: Vec<u8>,
    proto: SsrProtocol,
    obfs: SsrObfs,
    node: Node,
    target: SocketAddr,
    target_domain: Option<String>,
) -> anyhow::Result<()> {
    let conf = CipherConf::for_method(&method)?;

    // Split streams so read and write directions are independent.
    let (mut server_read, mut server_write) = server.into_split();

    match proto {
        SsrProtocol::AuthSha1V4 => {
            let auth_header = ShadowsocksRHandler::build_auth_sha1_v4_header(&master_key);
            server_write.write_all(&auth_header).await?;
            debug!(
                "SSR: auth_sha1_v4 header sent ({} bytes)",
                auth_header.len()
            );

            // Read 2-byte response from server (usually a status code).
            let mut resp = [0u8; AUTH_SHA1_V4_RESPONSE_LEN];
            server_read.read_exact(&mut resp).await?;
            debug!("SSR: auth_sha1_v4 server response: {:02x?}", resp);
        }
        SsrProtocol::Origin => {
            debug!("SSR: origin protocol (no auth header)");
        }
    }

    // Send obfuscation hello (if any).
    match obfs {
        SsrObfs::HttpSimple => {
            let obfs_header = ShadowsocksRHandler::build_http_simple_header(
                &node,
                target,
                target_domain.as_deref(),
            );
            server_write.write_all(&obfs_header).await?;
            debug!("SSR: http_simple header sent ({} bytes)", obfs_header.len());
            // http_simple server echoes back the same header structure.
            // We need to skip the server's echo by reading until "\r\n\r\n".
            let mut buf = [0u8; 4096];
            let mut echo_buf = Vec::new();
            loop {
                let n = server_read.read(&mut buf).await?;
                if n == 0 {
                    anyhow::bail!("SSR http_simple: connection closed during echo phase");
                }
                echo_buf.extend_from_slice(&buf[..n]);
                if echo_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    debug!("SSR: http_simple echo received ({} bytes)", echo_buf.len());
                    break;
                }
                if echo_buf.len() > 16384 {
                    anyhow::bail!("SSR http_simple: header too large");
                }
            }
        }
        SsrObfs::Plain => {
            debug!("SSR: plain obfs (no obfuscation header)");
        }
    }

    // SS AEAD handshake (salt + subkey exchange).
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

    let (mut client_read, mut client_write) = tokio::io::split(client);

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

// Shared helpers (duplicated from shadowsocks.rs for module independence).

/// Encrypt `payload` as Shadowsocks chunks and write them to the server.
async fn write_chunks<W>(
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
fn hkdf_sha1_derive(master_key: &[u8], salt: &[u8], okm: &mut [u8]) {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    hk.expand(SS_SUBKEY_INFO, okm)
        .expect("valid HKDF output length");
}

/// Increment a nonce treating it as a little-endian counter.
fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        if *byte == 0xFF {
            *byte = 0;
        } else {
            *byte += 1;
            break;
        }
    }
}

/// HMAC-SHA1 implementation to avoid the `hmac` crate's digest version conflict.
///
/// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
/// where H = SHA1, block size = 64 bytes.
fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};

    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5C;

    // Step 1: key preparation
    let mut k0 = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = Sha1::digest(key);
        k0[..hashed.len()].copy_from_slice(&hashed);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    // Step 2: inner hash H((K' ⊕ ipad) || message)
    let mut inner = Sha1::new();
    let mut ipadded = [0u8; BLOCK_SIZE];
    for (i, b) in k0.iter().enumerate() {
        ipadded[i] = b ^ IPAD;
    }
    inner.update(ipadded);
    inner.update(message);
    let inner_hash = inner.finalize();

    // Step 3: outer hash H((K' ⊕ opad) || inner_hash)
    let mut outer = Sha1::new();
    let mut opadded = [0u8; BLOCK_SIZE];
    for (i, b) in k0.iter().enumerate() {
        opadded[i] = b ^ OPAD;
    }
    outer.update(opadded);
    outer.update(inner_hash);
    outer.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_proto_origin_default() {
        let node = Node::default();
        assert_eq!(SsrProtocol::from_node(&node), SsrProtocol::Origin);
    }

    #[test]
    fn test_proto_auth_sha1_v4() {
        let node = Node {
            plugin: Some("auth_sha1_v4".to_string()),
            ..Default::default()
        };
        assert_eq!(SsrProtocol::from_node(&node), SsrProtocol::AuthSha1V4);
    }

    #[test]
    fn test_proto_auth_aes128_fallback() {
        let node = Node {
            plugin: Some("auth_aes128_md5".to_string()),
            ..Default::default()
        };
        // Not yet implemented — falls back to Origin.
        assert_eq!(SsrProtocol::from_node(&node), SsrProtocol::Origin);
    }

    #[test]
    fn test_obfs_plain_default() {
        let node = Node::default();
        assert_eq!(SsrObfs::from_node(&node), SsrObfs::Plain);
    }

    #[test]
    fn test_obfs_http_simple() {
        let node = Node {
            plugin: Some("http_simple".to_string()),
            ..Default::default()
        };
        assert_eq!(SsrObfs::from_node(&node), SsrObfs::HttpSimple);
    }

    #[test]
    fn test_obfs_tls12_fallback() {
        let node = Node {
            plugin: Some("tls1.2_ticket_auth".to_string()),
            ..Default::default()
        };
        // Not yet implemented — falls back to Plain.
        assert_eq!(SsrObfs::from_node(&node), SsrObfs::Plain);
    }

    #[test]
    fn test_parse_obfs_opts() {
        let node = Node {
            plugin_opts: Some("obfs-host=cloudflare.com;obfs-uri=/api".to_string()),
            ..Default::default()
        };
        let opts = SsrObfs::parse_opts(&node);
        assert_eq!(opts.get("obfs-host"), Some(&"cloudflare.com"));
        assert_eq!(opts.get("obfs-uri"), Some(&"/api"));
    }

    #[test]
    fn test_parse_obfs_opts_empty() {
        let node = Node::default();
        let opts = SsrObfs::parse_opts(&node);
        assert!(opts.is_empty());
    }

    #[test]
    fn test_evp_bytes_to_key() {
        let key = ShadowsocksRHandler::master_key("foobar", 32);
        assert_eq!(key.len(), 32);
        // MD5("foobar") == 3858f62230ac3c915f300c664312c63f
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
        let encoded = ShadowsocksRHandler::encode_address(target, None);
        assert_eq!(encoded[0], 0x01);
        assert_eq!(&encoded[1..5], &[93, 184, 216, 34]);
        assert_eq!(&encoded[5..7], &[0x00, 0x50]);
    }

    #[test]
    fn test_address_encoding_domain() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443));
        let encoded = ShadowsocksRHandler::encode_address(target, Some("example.com"));
        assert_eq!(encoded[0], 0x03);
        assert_eq!(encoded[1], 11);
        assert_eq!(&encoded[2..13], b"example.com");
        assert_eq!(&encoded[13..15], &[0x01, 0xbb]);
    }

    #[test]
    fn test_auth_sha1_v4_header_format() {
        let master_key = b"0123456789abcdef";
        let header = ShadowsocksRHandler::build_auth_sha1_v4_header(master_key);
        // 4 bytes client_id + 10 bytes HMAC + 4 bytes timestamp = 18 bytes
        assert_eq!(header.len(), 18);
    }

    #[test]
    fn test_auth_sha1_v4_header_deterministic_hmac() {
        // HMAC-SHA1 must be deterministic: same inputs → same output.
        let master_key = b"test-master-key";
        let client_id: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let ts: u32 = 1700000000u32;
        let ts_bytes = ts.to_be_bytes();

        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&client_id);
        data.extend_from_slice(&ts_bytes);

        let result1 = hmac_sha1(master_key, &data);
        let result2 = hmac_sha1(master_key, &data);

        // Same inputs must produce identical output.
        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 20); // SHA1 produces 20 bytes

        // Different key produces different output.
        let different = hmac_sha1(b"other-key", &data);
        assert_ne!(result1, different);

        // Different message produces different output.
        let mut other_data = data.clone();
        other_data[0] ^= 1;
        let different2 = hmac_sha1(master_key, &other_data);
        assert_ne!(result1, different2);
    }

    #[test]
    fn test_cipher_conf_lookup() {
        assert!(CipherConf::for_method("aes-128-gcm").is_ok());
        assert!(CipherConf::for_method("AES-256-GCM").is_ok());
        assert!(CipherConf::for_method("chacha20-ietf-poly1305").is_ok());
        assert!(CipherConf::for_method("chacha20-poly1305").is_ok());
        assert!(CipherConf::for_method("rc4-md5").is_err());
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
    fn test_http_simple_header_format() {
        let node = Node {
            plugin: Some("http_simple".to_string()),
            plugin_opts: Some("obfs-host=example.com".to_string()),
            ..Default::default()
        };
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let header =
            ShadowsocksRHandler::build_http_simple_header(&node, target, Some("example.com"));
        let s = String::from_utf8(header).unwrap();
        assert!(s.starts_with("GET "));
        assert!(s.contains("Host: example.com"));
        assert!(s.contains("User-Agent: curl/7.100.0"));
        assert!(s.ends_with("\r\n\r\n"));
    }
}
