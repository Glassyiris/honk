use super::*;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::AsyncReadExt;

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
fn test_legacy_udp_roundtrip() {
    let crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
    let socks = addr::encode_address(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
        None,
    )
    .unwrap();
    let payload = b"\xde\xad\xbe\xef dns query";
    let packet = crypto.seal(&socks, payload).unwrap();
    // salt + tag minimum
    assert!(packet.len() > 16 + 16 + payload.len());
    let opened = crypto.open(&packet).unwrap();
    assert_eq!(opened, payload);
}

#[tokio::test]
async fn udp_send_waits_for_cipher_instead_of_reporting_a_drop_as_success() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(server.local_addr().unwrap()).await.unwrap();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = Arc::new(SsUdpTransport {
        socket: client,
        crypto: tokio::sync::Mutex::new(SsUdpCrypto::Legacy(
            LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap(),
        )),
        recv_buf: tokio::sync::Mutex::new(None),
        socks: addr::encode_address(target, None).unwrap(),
        target,
    });
    let guard = transport.crypto.lock().await;
    let sender = {
        let transport = Arc::clone(&transport);
        tokio::spawn(async move { transport.send_packet(b"retained").await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(
        !sender.is_finished(),
        "cipher contention must apply backpressure instead of returning false success"
    );

    drop(guard);
    sender.await.unwrap().unwrap();
    let mut packet = [0u8; 256];
    let received =
        tokio::time::timeout(std::time::Duration::from_secs(1), server.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
    assert!(received > b"retained".len());
}

#[test]
fn test_legacy_udp_roundtrip_chacha() {
    let crypto = LegacyUdpCrypto::new("chacha20-ietf-poly1305", "test-password").unwrap();
    let socks = addr::encode_address(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443)),
        Some("one.one"),
    )
    .unwrap();
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

/// Batched seal/decrypt equivalence: any payload round-trips through
/// `seal_chunks_into` + `decrypt_chunks_in_place` in one batch.
#[test]
fn test_batched_chunk_roundtrip() {
    let cipher = AeadCipher::new("aes-128-gcm", &ShadowsocksHandler::master_key("pw", 16)).unwrap();
    for payload_len in [0usize, 1, 100, CHUNK_MAX_LEN, CHUNK_MAX_LEN + 17, 100_000] {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let mut send_nonce = vec![0u8; 12];
        let mut sealed = Vec::new();
        seal_chunks_into(&cipher, &mut send_nonce, &payload, &mut sealed).unwrap();
        assert_eq!(
            sealed.len(),
            payload_len + payload_len.div_ceil(CHUNK_MAX_LEN) * (2 + 16 + 16)
        );

        let mut recv_nonce = vec![0u8; 12];
        let mut buf = sealed;
        let total = buf.len();
        let (out_len, carry) =
            decrypt_chunks_in_place(&cipher, &mut recv_nonce, &mut None, &mut buf, total, 16)
                .unwrap();
        assert_eq!(carry, 0, "complete batch must leave no carry");
        assert_eq!(&buf[..out_len], payload.as_slice());
    }
}

/// Split feeds: chunks spanning batch boundaries must be carried and
/// completed by the next feed.
#[test]
fn test_batched_decrypt_split_feeds() {
    let cipher = AeadCipher::new("aes-128-gcm", &ShadowsocksHandler::master_key("pw", 16)).unwrap();
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();
    let mut send_nonce = vec![0u8; 12];
    let mut sealed = Vec::new();
    seal_chunks_into(&cipher, &mut send_nonce, &payload, &mut sealed).unwrap();

    let mut recv_nonce = vec![0u8; 12];
    let mut pending = None;
    let mut received = Vec::new();
    let mut carry_buf = vec![0u8; 0];
    // Feed in awkward slices that split len fields and chunk bodies.
    for slice_len in [1usize, 3, 7, 8192, 5, 4096, 65536] {
        let take = slice_len.min(sealed.len());
        let mut feed = carry_buf.clone();
        feed.extend_from_slice(&sealed[..take]);
        sealed.drain(..take);
        let total = feed.len();
        let (out_len, rest) =
            decrypt_chunks_in_place(&cipher, &mut recv_nonce, &mut pending, &mut feed, total, 16)
                .unwrap();
        received.extend_from_slice(&feed[..out_len]);
        carry_buf = feed[out_len..out_len + rest].to_vec();
    }
    assert!(sealed.is_empty());
    let total = carry_buf.len();
    let (out_len, rest) = decrypt_chunks_in_place(
        &cipher,
        &mut recv_nonce,
        &mut pending,
        &mut carry_buf,
        total,
        16,
    )
    .unwrap();
    received.extend_from_slice(&carry_buf[..out_len]);
    assert_eq!(rest, 0);
    assert_eq!(received, payload);
}

/// End-to-end TCP test: mock legacy-AEAD TCP server (salt + chunk
/// codec), real `dial` through the inline `SsStream`, bulk data both
/// ways (chunk boundaries crossed many times).
#[tokio::test]
async fn test_dial_tcp_legacy_end_to_end() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut server, _) = listener.accept().await.unwrap();
        let method = "aes-128-gcm";
        let password = "test-password";
        let conf = CipherConf::for_method(method).unwrap();
        let master = ShadowsocksHandler::master_key(password, conf.key_len);

        // Read the client salt + derive the c2s cipher.
        let mut c2s_salt = vec![0u8; conf.salt_len];
        server.read_exact(&mut c2s_salt).await.unwrap();
        let mut c2s_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&master, &c2s_salt, &mut c2s_subkey);
        let c2s_cipher = AeadCipher::new(method, &c2s_subkey).unwrap();
        let mut c2s_nonce = vec![0u8; conf.nonce_len];

        // Send our salt back.
        let mut s2c_salt = vec![0u8; conf.salt_len];
        rand::rng().fill_bytes(&mut s2c_salt);
        server.write_all(&s2c_salt).await.unwrap();
        let mut s2c_subkey = vec![0u8; conf.key_len];
        hkdf_sha1_derive(&master, &s2c_salt, &mut s2c_subkey);
        let s2c_cipher = AeadCipher::new(method, &s2c_subkey).unwrap();
        let mut s2c_nonce = vec![0u8; conf.nonce_len];

        // Echo loop: decrypt chunks, uppercase the payload, re-seal.
        // The first plaintext bytes are the target header (own chunk);
        // skip them, echo the rest.
        let header_len = 7usize; // atyp + v4 + port of 93.184.216.34:80
        let mut skip = header_len;
        let mut buf = vec![0u8; 262144];
        let mut carry = 0usize;
        let mut pending_len = None;
        loop {
            let n = server.read(&mut buf[carry..]).await.unwrap();
            if n == 0 {
                return;
            }
            let total = carry + n;
            let (out_len, rest) = decrypt_chunks_in_place(
                &c2s_cipher,
                &mut c2s_nonce,
                &mut pending_len,
                &mut buf,
                total,
                conf.tag_len,
            )
            .unwrap();
            if out_len > 0 {
                let start = skip.min(out_len);
                skip -= start;
                if start < out_len {
                    let upper: Vec<u8> = buf[start..out_len]
                        .iter()
                        .map(|b| b.to_ascii_uppercase())
                        .collect();
                    let mut sealed = Vec::new();
                    seal_chunks_into(&s2c_cipher, &mut s2c_nonce, &upper, &mut sealed).unwrap();
                    server.write_all(&sealed).await.unwrap();
                }
            }
            if rest > 0 {
                buf.copy_within(out_len..out_len + rest, 0);
            }
            carry = rest;
        }
    });

    let node = Node {
        name: "test-ss-tcp".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some("aes-128-gcm".into()),
                password: Some("test-password".into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let mut stream = handler
        .dial(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();

    // Bulk transfer both ways: ~1MB in 8 uneven writes.
    let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    let mut off = 0;
    for chunk in [3usize, 65536, 17, 262144, 999, 400_000, 131071, 271_329] {
        let end = (off + chunk).min(payload.len());
        stream.stream.write_all(&payload[off..end]).await.unwrap();
        off = end;
    }
    assert_eq!(off, payload.len());

    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.stream.read_exact(&mut received),
    )
    .await
    .expect("echo timed out")
    .unwrap();
    let expected: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
    assert_eq!(received, expected);
}

/// End-to-end UDP test over the real framed `dial_udp_transport` path.
#[tokio::test]
async fn test_dial_udp_transport_legacy_end_to_end() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_crypto = LegacyUdpCrypto::new("aes-128-gcm", "test-password").unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            let payload = server_crypto.open(&buf[..n]).unwrap();
            let reply: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
            let socks = addr::encode_address("8.8.8.8:53".parse().unwrap(), None).unwrap();
            let packet = server_crypto.seal(&socks, &reply).unwrap();
            server.send_to(&packet, src).await.unwrap();
        }
    });

    let node = Node {
        name: "test-ss-udp".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some("aes-128-gcm".into()),
                password: Some("test-password".into()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let transport = handler
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    assert_eq!(transport.relay_addr(), target);

    let payload = [b'a'; 1200];
    let mut buf = [0u8; 1200];
    let (received, sent) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(biased; transport.recv_packet(&mut buf), transport.send_packet(&payload))
    })
    .await
    .expect("pending receive must not block the send that elicits its reply");
    sent.unwrap();
    let (n, src) = received.unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], &[b'A'; 1200]);
}
