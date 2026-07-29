//! VMess AEAD outbound handler.
//!
//! Implements VMess AEAD protocol (V2Ray v4.28.1+) with `alterId=0`.
//!
//! The connection is established through the shared transport layer
//! (`super::transport`): TCP, optionally TLS-wrapped, optionally carried
//! over WebSocket (`node.transport = "ws"`) or gRPC (`"grpc"`). The VMess
//! handshake then runs on the resulting stream.
//!
//! Protocol overview:
//!
//! 1. **Key derivation**:
//!    - `cmd_key = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`
//!    - `auth_key = MD5(uuid)`
//!
//! 2. **Auth header** (sent to server):
//!    ```text
//!    auth_id(16) | cmd_nonce(12) | encrypted_instruction
//!    ```
//!    - `auth_id`: AES-128-GCM(key=auth_key, nonce=timestamp||0x00000000,
//!      plaintext=[])[0..16]
//!    - `encrypted_instruction`: AES-128-GCM(key=cmd_key, nonce=cmd_nonce,
//!      plaintext=instruction)
//!
//! 3. **Instruction** (plaintext, 55–71+ bytes):
//!    ```text
//!    version(1) | body_key(16) | body_iv(16) | resp_header(1) |
//!    options(1) | padding_len(2) | padding(P) | resp_key(16) | resp_iv(16)
//!    ```
//!
//! 4. **Address** (encrypted with body_key, nonce = body_iv[..12]):
//!    - V2Ray ATYP format: `ATYP(1) | addr | port(2)`
//!    - IPv4: ATYP=0x01 + 4 bytes
//!    - Domain: ATYP=0x02 + 1-byte len + domain
//!    - IPv6: ATYP=0x03 + 16 bytes
//!
//! 5. **Data relay** (authenticated-length chunks):
//!    - Each chunk: `[2+16 bytes: encrypted_len] [N+16 bytes: encrypted_payload]`
//!    - Nonce starts at body_iv[..12] + 1 (counter 1) for send
//!    - Nonce starts at resp_iv[..12] (counter 0) for receive
//!
//! Reference: <https://www.v2fly.org/developer/protocols/vmess.html>

use aes_gcm::aead::{Aead, KeyInit};
use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use md5::{Digest, Md5};
use rand::Rng;
use rand::RngExt;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::addr::{self, SocksAddr};
use super::{AsyncReadWrite, ProxyHandler, ProxyStream};

/// VMess AEAD version byte.
const VMESS_VERSION: u8 = 0x01;
/// Options: Standard format (target address directly follows instruction cipher).
const OPT_S: u8 = 0x01;
/// Options: Authenticated length (each data chunk prefixed with a 2-byte
/// length encrypted in its own AEAD block, a.k.a. ChunkStream).
const OPT_A: u8 = 0x04;
/// Response header obfuscation length (0 = disabled).
const RESP_HEADER_LEN: u8 = 0x00;
/// Suffix for cmd_key derivation.
const CMD_KEY_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
/// AES-GCM tag length in bytes.
const GCM_TAG_LEN: usize = 16;
/// AES-128-GCM nonce length.
const NONCE_LEN: usize = 12;
/// Maximum plaintext payload per AEAD chunk (same as Shadowsocks).
const CHUNK_MAX_LEN: usize = 0x3FFF; // 16383;

/// VMess AEAD proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct VmessHandler;

impl VmessHandler {
    pub fn new() -> Self {
        Self
    }

    /// Encode target address in the V2Ray ATYP format (domain = 0x02,
    /// IPv6 = 0x03 — not the SOCKS5 numbering).
    fn encode_address(target: SocketAddr, target_domain: Option<&str>) -> Vec<u8> {
        let socks = SocksAddr::new(target, target_domain);
        let mut buf = Vec::with_capacity(socks.encoded_len());
        socks.encode_with(&mut buf, addr::ATYP_VMESS);
        buf
    }

    /// Derive the command key: `MD5(uuid || CMD_KEY_SUFFIX)`.
    fn derive_cmd_key(uuid: &[u8]) -> [u8; 16] {
        let mut h = Md5::new();
        h.update(uuid);
        h.update(CMD_KEY_SUFFIX);
        h.finalize().into()
    }

    /// Derive the auth key: `MD5(uuid)`.
    fn derive_auth_key(uuid: &[u8]) -> [u8; 16] {
        let mut h = Md5::new();
        h.update(uuid);
        h.finalize().into()
    }

    /// Build the `auth_id` field: first 16 bytes of AES-128-GCM with an
    /// empty plaintext, keyed with `auth_key` and nonced with the current
    /// unix timestamp.
    fn build_auth_id(uuid: &[u8]) -> ([u8; 16], u64) {
        let auth_key = Self::derive_auth_key(uuid);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts_bytes = ts.to_be_bytes();

        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&ts_bytes);

        let cipher = aes_gcm::Aes128Gcm::new_from_slice(&auth_key).expect("valid key length");
        let ct = cipher
            .encrypt(
                <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                    .expect("nonce size"),
                [].as_ref(),
            )
            .expect("encrypt empty plaintext");

        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&ct[..16]);
        (auth_id, ts)
    }

    /// Build the plaintext instruction block and its random nonce.
    fn build_instruction(
        body_key: &[u8; 16],
        body_iv: &[u8; 16],
        resp_key: &[u8; 16],
        resp_iv: &[u8; 16],
    ) -> ([u8; NONCE_LEN], Vec<u8>) {
        let mut rng = rand::rng();
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let padding_len: u16 = rng.random_range(0..=16);
        let capacity = 1 + 16 + 16 + 1 + 1 + 2 + padding_len as usize + 16 + 16;
        let mut plain = Vec::with_capacity(capacity);

        plain.push(VMESS_VERSION); // 1
        plain.extend_from_slice(body_key); // 16
        plain.extend_from_slice(body_iv); // 16
        plain.push(RESP_HEADER_LEN); // 1
        plain.push(OPT_S | OPT_A); // 1
        plain.extend_from_slice(&padding_len.to_be_bytes()); // 2
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len as usize];
            rng.fill_bytes(&mut padding);
            plain.extend_from_slice(&padding); // P
        }
        plain.extend_from_slice(resp_key); // 16
        plain.extend_from_slice(resp_iv); // 16

        (nonce, plain)
    }

    /// Encrypt the instruction with the command key.
    fn encrypt_instruction(cmd_key: &[u8; 16], nonce: &[u8; NONCE_LEN], plain: &[u8]) -> Vec<u8> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(cmd_key).expect("valid key length");
        cipher
            .encrypt(
                <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                    .expect("nonce size"),
                plain,
            )
            .expect("encrypt instruction")
    }

    /// Encrypt plaintext with AES-128-GCM.
    fn seal(key: &[u8; 16], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("valid key length");
        cipher
            .encrypt(
                <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                    .expect("nonce size"),
                plaintext,
            )
            .expect("seal")
    }

    /// Decrypt ciphertext with AES-128-GCM.
    fn open(
        key: &[u8; 16],
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("valid key length");
        cipher.decrypt(
            <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                .expect("nonce size"),
            ciphertext,
        )
    }

    async fn connect_server(
        node: &Node,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        super::transport::connect_transport(node, connect_timeout).await
    }

    /// Wrap an already-connected TCP stream with TLS (when `node.tls`) and
    /// then the `node.transport` WS/gRPC layer (the `dial_with_tcp` path).
    async fn wrap_transport(
        node: &Node,
        tcp: TcpStream,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        super::transport::wrap_transport(node, tcp).await
    }

    /// Perform the VMess AEAD handshake and return a proxy stream backed by
    /// a duplex pipe + background relay task.
    fn perform_handshake(
        uuid_bytes: &[u8],
        stream: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> anyhow::Result<ProxyStream> {
        let cmd_key = Self::derive_cmd_key(uuid_bytes);
        let (auth_id, _ts) = Self::build_auth_id(uuid_bytes);

        let mut rng = rand::rng();
        let mut body_key = [0u8; 16];
        let mut body_iv = [0u8; 16];
        let mut resp_key = [0u8; 16];
        let mut resp_iv = [0u8; 16];
        rng.fill_bytes(&mut body_key);
        rng.fill_bytes(&mut body_iv);
        rng.fill_bytes(&mut resp_key);
        rng.fill_bytes(&mut resp_iv);

        let (cmd_nonce, instruction) =
            Self::build_instruction(&body_key, &body_iv, &resp_key, &resp_iv);
        let encrypted_instruction = Self::encrypt_instruction(&cmd_key, &cmd_nonce, &instruction);

        let addr = Self::encode_address(target, target_domain);
        // Nonce for address: first 12 bytes of body_iv (counter 0).
        let addr_nonce: [u8; NONCE_LEN] = body_iv[..NONCE_LEN]
            .try_into()
            .expect("body_iv has >12 bytes");
        let encrypted_addr = Self::seal(&body_key, &addr_nonce, &addr);

        let (client_half, server_half) = tokio::io::duplex(65536);

        // Relay starts at counter 1 for send, counter 0 for receive.
        let send_start_nonce: [u8; NONCE_LEN] = addr_nonce;
        let recv_start_nonce: [u8; NONCE_LEN] = resp_iv[..NONCE_LEN]
            .try_into()
            .expect("resp_iv has >12 bytes");

        tokio::spawn(vmess_relay(
            stream,
            server_half,
            auth_id,
            cmd_nonce,
            encrypted_instruction,
            body_key,
            send_start_nonce,
            resp_key,
            recv_start_nonce,
            encrypted_addr,
        ));

        Ok(ProxyStream {
            stream: Box::new(client_half),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[async_trait]
impl ProxyHandler for VmessHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::VMess
    }

    /// With `mux` the dial goes through the h2mux SessionPool: bare-TCP
    /// pooling would force a new h2 session per flow (see AnyTlsHandler).
    fn pool_bare_tcp(&self, node: &Node) -> bool {
        !node.mux
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let password = node.password.as_deref().unwrap_or("");
        let uuid = uuid::Uuid::parse_str(password)
            .map_err(|e| anyhow::anyhow!("invalid VMess UUID: {}", e))?;
        let uuid_bytes = uuid.as_bytes();

        let stream = Self::connect_server(node, connect_timeout).await?;
        Self::perform_handshake(uuid_bytes, stream, target, target_domain)
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        _connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let password = node.password.as_deref().unwrap_or("");
        let uuid = uuid::Uuid::parse_str(password)
            .map_err(|e| anyhow::anyhow!("invalid VMess UUID: {}", e))?;
        let uuid_bytes = uuid.as_bytes();

        let stream = Self::wrap_transport(node, tcp).await?;
        Self::perform_handshake(uuid_bytes, stream, target, target_domain)
    }
}

/// Background task that encrypts client→server data and decrypts
/// server→client data using the VMess AEAD chunking format.
///
/// On the send side, counter 0 was already consumed for the target address,
/// so the relay starts at counter 1.  On the receive side the counter
/// starts at 0.
#[allow(clippy::too_many_arguments)]
async fn vmess_relay(
    server: Box<dyn AsyncReadWrite>,
    client: tokio::io::DuplexStream,
    auth_id: [u8; 16],
    cmd_nonce: [u8; NONCE_LEN],
    encrypted_instruction: Vec<u8>,
    body_key: [u8; 16],
    mut send_nonce: [u8; NONCE_LEN],
    resp_key: [u8; 16],
    mut recv_nonce: [u8; NONCE_LEN],
    encrypted_addr: Vec<u8>,
) -> anyhow::Result<()> {
    let (mut server_read, mut server_write) = tokio::io::split(server);
    let (mut client_read, mut client_write) = tokio::io::split(client);

    // Bump send_nonce once — counter 0 was the address.
    increment_nonce(&mut send_nonce);

    let c2s = async {
        // Write the VMess header: auth_id(16) + cmd_nonce(12) + encrypted_instruction
        server_write.write_all(&auth_id).await?;
        server_write.write_all(&cmd_nonce).await?;
        server_write.write_all(&encrypted_instruction).await?;

        // Write the encrypted address (counter 0, already sealed).
        server_write.write_all(&encrypted_addr).await?;

        let mut buf = vec![0u8; 65536];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_vmess_chunks(&mut server_write, &body_key, &mut send_nonce, &buf[..n]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let s2c = async {
        // Each chunk: [encrypted_len (2 + GCM_TAG_LEN)] [encrypted_payload]
        let mut len_buf = vec![0u8; 2 + GCM_TAG_LEN];
        loop {
            if server_read.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len_plain = open_resp(&resp_key, &recv_nonce, &len_buf)?;
            increment_nonce(&mut recv_nonce);

            let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

            let mut payload = vec![0u8; payload_len + GCM_TAG_LEN];
            server_read.read_exact(&mut payload).await?;

            let plain = open_resp(&resp_key, &recv_nonce, &payload)?;
            increment_nonce(&mut recv_nonce);

            client_write.write_all(&plain).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = c2s => r,
        r = s2c => r,
    }
}

/// Decrypt response data (thin wrapper that maps the error).
fn open_resp(
    key: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    VmessHandler::open(key, nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("VMess decrypt response failed: {:?}", e))
}

/// Write a payload as one or more authenticated-length VMess chunks.
async fn write_vmess_chunks<W>(
    writer: &mut W,
    body_key: &[u8; 16],
    nonce: &mut [u8; NONCE_LEN],
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + CHUNK_MAX_LEN).min(payload.len());
        let chunk = &payload[offset..end];

        // Encrypt the 2-byte length in its own AEAD block.
        let len = chunk.len() as u16;
        let len_plain = len.to_be_bytes();
        let len_cipher = VmessHandler::seal(body_key, nonce, &len_plain);
        increment_nonce(nonce);

        // Encrypt the payload in the next AEAD block.
        let payload_cipher = VmessHandler::seal(body_key, nonce, chunk);
        increment_nonce(nonce);

        writer.write_all(&len_cipher).await?;
        writer.write_all(&payload_cipher).await?;

        offset = end;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_cmd_key() {
        let uuid = [0u8; 16];
        let cmd_key = VmessHandler::derive_cmd_key(&uuid);
        assert_eq!(cmd_key.len(), 16);
        assert_ne!(cmd_key, [0u8; 16]);
    }

    #[test]
    fn test_derive_auth_key() {
        let uuid = [0u8; 16];
        let auth_key = VmessHandler::derive_auth_key(&uuid);
        assert_eq!(auth_key.len(), 16);
        assert_ne!(auth_key, [0u8; 16]);
    }

    #[test]
    fn test_cmd_key_deterministic() {
        let uuid = [1u8; 16];
        let k1 = VmessHandler::derive_cmd_key(&uuid);
        let k2 = VmessHandler::derive_cmd_key(&uuid);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_different_keys_for_different_uuids() {
        let k1 = VmessHandler::derive_cmd_key(&[0u8; 16]);
        let k2 = VmessHandler::derive_cmd_key(&[1u8; 16]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_build_auth_id_returns_16_bytes() {
        let uuid = [0u8; 16];
        let (auth_id, ts) = VmessHandler::build_auth_id(&uuid);
        assert_eq!(auth_id.len(), 16);
        assert!(ts > 1_700_000_000); // after 2023
    }

    #[test]
    fn test_auth_id_is_not_all_zeros() {
        let uuid = [0u8; 16];
        let (auth_id, _) = VmessHandler::build_auth_id(&uuid);
        assert_ne!(auth_id, [0u8; 16]);
    }

    #[test]
    fn test_build_instruction_structure() {
        let bk = [0u8; 16];
        let bi = [0u8; 16];
        let rk = [0u8; 16];
        let ri = [0u8; 16];

        let (nonce, inst) = VmessHandler::build_instruction(&bk, &bi, &rk, &ri);
        assert_eq!(nonce.len(), 12);

        assert_eq!(inst[0], VMESS_VERSION);
        assert_eq!(&inst[1..17], &bk);
        assert_eq!(&inst[17..33], &bi);
        assert_eq!(inst[33], RESP_HEADER_LEN);
        assert_eq!(inst[34], OPT_S | OPT_A);

        let padding_len = u16::from_be_bytes([inst[35], inst[36]]) as usize;
        let padding_end = 37 + padding_len;
        assert_eq!(&inst[padding_end..padding_end + 16], &rk);
        assert_eq!(&inst[padding_end + 16..padding_end + 32], &ri);
    }

    #[test]
    fn test_encrypt_instruction_roundtrip() {
        let bk = [1u8; 16];
        let bi = [2u8; 16];
        let rk = [3u8; 16];
        let ri = [4u8; 16];

        let uuid = [5u8; 16];
        let cmd_key = VmessHandler::derive_cmd_key(&uuid);
        let (nonce, inst) = VmessHandler::build_instruction(&bk, &bi, &rk, &ri);

        let encrypted = VmessHandler::encrypt_instruction(&cmd_key, &nonce, &inst);

        let decrypted =
            VmessHandler::open(&cmd_key, &nonce, &encrypted).expect("decrypt instruction");
        assert_eq!(decrypted, inst);
    }

    #[test]
    fn test_increment_nonce_basic() {
        let mut n = [0u8; 12];
        increment_nonce(&mut n);
        assert_eq!(n, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_increment_nonce_carry() {
        let mut n = [0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        increment_nonce(&mut n);
        assert_eq!(n, [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_increment_nonce_overflow() {
        let mut n = [0xFF; 12];
        increment_nonce(&mut n);
        assert_eq!(n, [0; 12]);
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let key = [0xAA; 16];
        let nonce = [0xBB; 12];
        let plain = b"hello vmess aead";

        let ct = VmessHandler::seal(&key, &nonce, plain);
        assert_eq!(ct.len(), plain.len() + GCM_TAG_LEN);

        let decrypted = VmessHandler::open(&key, &nonce, &ct).expect("decrypt");
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_seal_open_empty() {
        let key = [0xCC; 16];
        let nonce = [0xDD; 12];
        let plain: &[u8] = &[];

        let ct = VmessHandler::seal(&key, &nonce, plain);
        assert_eq!(ct.len(), GCM_TAG_LEN);

        let decrypted = VmessHandler::open(&key, &nonce, &ct).expect("decrypt empty");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_open_with_wrong_key_fails() {
        let key1 = [0x11; 16];
        let key2 = [0x22; 16];
        let nonce = [0x33; 12];
        let ct = VmessHandler::seal(&key1, &nonce, b"data");
        assert!(VmessHandler::open(&key2, &nonce, &ct).is_err());
    }

    #[test]
    fn test_open_with_wrong_nonce_fails() {
        let key = [0x44; 16];
        let nonce1 = [0x55; 12];
        let nonce2 = [0x66; 12];
        let ct = VmessHandler::seal(&key, &nonce1, b"data");
        assert!(VmessHandler::open(&key, &nonce2, &ct).is_err());
    }

    #[test]
    fn test_protocol_returns_vmess() {
        let handler = VmessHandler;
        assert_eq!(handler.protocol(), NodeProtocol::VMess);
    }

    #[test]
    fn test_handler_new() {
        let _handler = VmessHandler::new();
    }

    /// End-to-end over the WebSocket transport: a mock WS server receives
    /// the VMess auth block + encrypted address as binary message(s) and
    /// fully decrypts the instruction and target address.
    #[tokio::test]
    async fn test_vmess_dial_over_ws_handshake() {
        use futures_util::StreamExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "b831381d-6324-4d53-ad4f-8cda48b30811";

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            let uuid = uuid::Uuid::parse_str(uuid_str).unwrap();
            let cmd_key = VmessHandler::derive_cmd_key(uuid.as_bytes());
            let cmd_cipher = aes_gcm::Aes128Gcm::new_from_slice(&cmd_key).unwrap();

            // The bridge may coalesce or split the header writes; collect
            // binary messages until the instruction + address decrypt.
            // auth_id(16) | cmd_nonce(12) | enc_instruction | enc_addr;
            // instruction plaintext is 69..=85 bytes (+16 tag), the IPv4
            // address ciphertext is exactly 23 bytes.
            let mut data = Vec::new();
            let (instruction, addr_ct) = loop {
                let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
                    .await
                    .expect("message within timeout")
                    .expect("stream open")
                    .expect("message ok");
                data.extend_from_slice(&msg.into_data());

                if data.len() >= 28 + 85 + 23 {
                    let mut found = None;
                    for instr_ct_len in 85..=101 {
                        if 28 + instr_ct_len + 23 != data.len() {
                            continue;
                        }
                        let nonce: &[u8; NONCE_LEN] = data[16..28].try_into().unwrap();
                        if let Ok(pt) =
                            cmd_cipher.decrypt(nonce.into(), &data[28..28 + instr_ct_len])
                        {
                            found = Some((pt, data[28 + instr_ct_len..].to_vec()));
                            break;
                        }
                    }
                    if let Some(found) = found {
                        break found;
                    }
                    panic!("VMess header did not decrypt ({} bytes)", data.len());
                }
            };

            assert_eq!(instruction[0], VMESS_VERSION);
            assert_eq!(instruction[34], OPT_S | OPT_A);

            let body_key: [u8; 16] = instruction[1..17].try_into().unwrap();
            let body_iv: [u8; 16] = instruction[17..33].try_into().unwrap();
            let body_cipher = aes_gcm::Aes128Gcm::new_from_slice(&body_key).unwrap();
            let addr_nonce: &[u8; NONCE_LEN] = body_iv[..NONCE_LEN].try_into().unwrap();
            let addr = body_cipher
                .decrypt(addr_nonce.into(), addr_ct.as_slice())
                .expect("address decrypts");
            assert_eq!(addr[0], addr::ATYP_VMESS.ipv4);
            assert_eq!(&addr[1..5], &[93, 184, 216, 34]);
            assert_eq!(&addr[5..7], &[0x00, 0x50]); // port 80
        });

        let node = Node {
            name: "vmess-ws".into(),
            protocol: NodeProtocol::VMess,
            address: format!("127.0.0.1:{}", port),
            host: "127.0.0.1".into(),
            port,
            password: Some(uuid_str.into()),
            transport: "ws".into(),
            ws_path: Some("/vmess".into()),
            ..Default::default()
        };
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let _ps = VmessHandler::new()
            .dial(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}
