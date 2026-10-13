use super::*;
use crate::proxy::shadowsocks::ShadowsocksHandler;
use crate::proxy::{PacketOutbound, TcpOutbound};
use honk_config::node::Node;
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Fixed test material (same values fed to the Go reference program).
fn psk1() -> Vec<u8> {
    (0u8..16).collect()
}
fn psk2() -> Vec<u8> {
    (16u8..32).collect()
}
fn salt16() -> Vec<u8> {
    (32u8..48).collect()
}
fn psk32() -> Vec<u8> {
    (0u8..32).collect()
}
fn salt32() -> Vec<u8> {
    (32u8..64).collect()
}

#[test]
fn test_psk_parse_single() {
    let m = Ss2022Method::new("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==").unwrap();
    assert_eq!(m.psks.len(), 1);
    assert_eq!(m.psks[0], psk1());
    assert!(m.psk_hashes.is_empty());
}

#[test]
fn test_psk_parse_multi() {
    let m = Ss2022Method::new(
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
    )
    .unwrap();
    assert_eq!(m.psks.len(), 2);
    assert_eq!(m.encryption_psk(), &psk2()[..]);
    assert_eq!(m.psk_hashes.len(), 1);
    assert_eq!(m.psk_hashes[0], hex("ea5ff194405ece4f55ae7a150c523884")[..]);
}

#[test]
fn test_psk_parse_bad_length() {
    // 32-byte psk with a 16-byte method.
    assert!(
        Ss2022Method::new(
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        )
        .is_err()
    );
    // 16-byte psk with a 32-byte method.
    assert!(Ss2022Method::new("2022-blake3-aes-256-gcm", "AAECAwQFBgcICQoLDA0ODw==").is_err());
}

#[test]
fn test_psk_parse_bad_base64() {
    assert!(Ss2022Method::new("2022-blake3-aes-128-gcm", "!!!not-base64!!!").is_err());
    assert!(Ss2022Method::new("2022-blake3-aes-128-gcm", "").is_err());
}

#[test]
fn test_psk_parse_chacha_rejects_multi() {
    assert!(Ss2022Method::new(
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        )
        .is_err());
    assert!(
        Ss2022Method::new(
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        )
        .is_ok()
    );
}

// BLAKE3 known-answer tests (generated with the Go reference).

#[test]
fn test_session_subkey_kat() {
    let m = Ss2022Method::new("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==").unwrap();
    assert_eq!(
        m.session_subkey(&salt16()),
        hex("8180421f8f56092ca7544a64ff852536")
    );
}

#[test]
fn test_session_subkey_kat_32() {
    let m = Ss2022Method::new(
        "2022-blake3-aes-256-gcm",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    )
    .unwrap();
    assert_eq!(
        m.session_subkey(&salt32()),
        hex("374fca03e4dae7f998fd7e59c1edfcc8e3197f4db1c19ca1671be3b66a92ddda")
    );
}

#[test]
fn test_eih_kat() {
    // psk list [psk1, psk2], salt16 → single EIH block, KAT from Go
    // (AES-ECB(identity_subkey, blake3(psk2)[..16])).
    let m = Ss2022Method::new(
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
    )
    .unwrap();
    let eih = m.tcp_identity_headers(&salt16()).unwrap();
    assert_eq!(eih, hex("cfe4b97eb5c29f5dda417a22031c9f08"));
}

#[test]
fn test_aes_block_kat() {
    // AES-ECB(psk1)(0x01020304050607081122334455667788) KAT from Go.
    let block = AesBlock::new(&psk1()).unwrap();
    let mut data: [u8; 16] = hex("01020304050607081122334455667788").try_into().unwrap();
    block.encrypt(&mut data);
    assert_eq!(data, hex("838e4115229deb1b278e7474a56e1893")[..]);
    block.decrypt(&mut data);
    assert_eq!(data, hex("01020304050607081122334455667788")[..]);
}

#[test]
fn test_blake3_xof_kat() {
    let key: [u8; 32] = (0u8..32)
        .map(|i| i * 3)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let mut xof = Blake3Xof::with_key(key);
    let mut out = [0u8; 32];
    xof.fill(&mut out);
    assert_eq!(
        out,
        hex("4a77995a0df1a72023241481d0d6436f3ae93d3509691067cc834db52326b6c2")[..]
    );
}

#[test]
fn test_sliding_window() {
    let mut w = SlidingWindow::new();
    assert!(w.check(0));
    w.add(0);
    assert!(!w.check(0)); // replay
    assert!(w.check(1));
    w.add(1);
    assert!(!w.check(0));
    assert!(!w.check(1));
    // Jump far ahead: old values fall out of the window.
    w.add(SW_SIZE + 200);
    assert!(w.check(SW_SIZE + 201));
    assert!(!w.check(0)); // behind window
    assert!(w.check(SW_SIZE + 199));
    w.add(SW_SIZE + 199);
    assert!(!w.check(SW_SIZE + 199));
}

/// Length of the leading SOCKS5 address, parsed independently of production.
fn addr_len(buf: &[u8]) -> usize {
    match buf[0] {
        0x01 => 7,
        0x03 => 2 + buf[1] as usize + 2,
        0x04 => 19,
        atyp => panic!("unexpected ATYP {atyp:#x}"),
    }
}

fn udp_target() -> (Vec<u8>, SocketAddr) {
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    (
        crate::proxy::addr::encode_address(target, None).unwrap(),
        target,
    )
}

/// Server-side parse of an AES-construction client packet; returns
/// (session_id, packet_id, payload).
fn server_open_aes(method: &Ss2022Method, packet: &[u8]) -> (u64, u64, Vec<u8>) {
    let psk = method.encryption_psk();
    let mut plain_header: [u8; 16] = packet[..16].try_into().unwrap();
    AesBlock::new(psk).unwrap().decrypt(&mut plain_header);
    let session_id = u64::from_be_bytes(plain_header[..8].try_into().unwrap());
    let packet_id = u64::from_be_bytes(plain_header[8..].try_into().unwrap());

    let subkey = method.session_subkey(&plain_header[..8]);
    let cipher = method.aead(&subkey).unwrap();
    let body = cipher.open(&plain_header[4..16], &packet[16..]).unwrap();
    assert_eq!(body[0], HEADER_TYPE_CLIENT);
    let ts = u64::from_be_bytes(body[1..9].try_into().unwrap());
    assert!(unix_timestamp().abs_diff(ts) <= 30);
    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let rest = &body[11 + padding_len..];
    let skip = addr_len(rest);
    (session_id, packet_id, rest[skip..].to_vec())
}

/// Server-side build of a response packet for either UDP construction.
fn server_seal_udp(
    method: &Ss2022Method,
    client_session_id: u64,
    server_session_id: u64,
    server_packet_id: u64,
    timestamp: u64,
    socks: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut ids = [0u8; 16];
    ids[..8].copy_from_slice(&server_session_id.to_be_bytes());
    ids[8..].copy_from_slice(&server_packet_id.to_be_bytes());

    let mut body = Vec::with_capacity(16 + 19 + socks.len() + payload.len());
    if method.is_chacha() {
        body.extend_from_slice(&ids);
    }
    body.push(HEADER_TYPE_SERVER);
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&client_session_id.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(socks);
    body.extend_from_slice(payload);

    if method.is_chacha() {
        let cipher = AeadCipher::new_xchacha20(method.encryption_psk()).unwrap();
        let mut nonce = [0u8; UDP_XNONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);
        let sealed = cipher.seal(&nonce, &body).unwrap();
        let mut packet = nonce.to_vec();
        packet.extend_from_slice(&sealed);
        return packet;
    }

    let subkey = method.session_subkey(&ids[..8]);
    let cipher = method.aead(&subkey).unwrap();
    let sealed = cipher.seal(&ids[4..], &body).unwrap();
    let mut encrypted_ids = ids;
    AesBlock::new(method.encryption_psk())
        .unwrap()
        .encrypt(&mut encrypted_ids);
    let mut packet = encrypted_ids.to_vec();
    packet.extend_from_slice(&sealed);
    packet
}

#[test]
fn test_udp_2022_aes_roundtrip() {
    let psk_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let method = Ss2022Method::new("2022-blake3-aes-256-gcm", psk_b64).unwrap();
    let mut session = Ss2022UdpSession::new(method).unwrap();
    let server_method = Ss2022Method::new("2022-blake3-aes-256-gcm", psk_b64).unwrap();
    let (socks, target) = udp_target();

    let payload = b"dns query payload";
    let packet = session.seal_packet(&socks, target.port(), payload).unwrap();
    // DNS payload → padding present.
    assert!(packet.len() > 16 + 1 + 8 + 2 + socks.len() + payload.len() + TAG_LEN);

    let (session_id, packet_id, opened) = server_open_aes(&server_method, &packet);
    assert_eq!(packet_id, 0);
    assert_eq!(opened, payload);

    // Second packet increments the packet id.
    let packet2 = session.seal_packet(&socks, target.port(), payload).unwrap();
    let (_, packet_id2, _) = server_open_aes(&server_method, &packet2);
    assert_eq!(packet_id2, 1);

    // Server response.
    let response = server_seal_udp(
        &server_method,
        session_id,
        0xdeadbeef,
        0,
        unix_timestamp(),
        &socks,
        b"dns response",
    );
    let opened = session.open_packet(&response).unwrap();
    assert_eq!(opened.payload(), b"dns response");

    // Replay of the same packet must be rejected.
    assert!(session.open_packet(&response).is_err());
}

#[test]
fn test_udp_2022_aes_eih_multi_psk() {
    // Two psks: identity psk1 + encryption psk2 (16-byte AES method).
    let m = Ss2022Method::new(
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
    )
    .unwrap();
    let mut session = Ss2022UdpSession::new(m).unwrap();
    let (socks, target) = udp_target();
    let payload = b"hello";
    let packet = session.seal_packet(&socks, target.port(), payload).unwrap();
    // Layout: enc_header(16) | EIH(16) | body+tag.
    assert!(packet.len() > 32);

    // Decrypt the separate header with the FIRST psk (server identity psk).
    let mut plain_header: [u8; 16] = packet[..16].try_into().unwrap();
    AesBlock::new(&psk1()).unwrap().decrypt(&mut plain_header);

    // EIH block: AES-ECB(psk1, psk_hash XOR plain_header).
    let mut eih: [u8; 16] = packet[16..32].try_into().unwrap();
    AesBlock::new(&psk1()).unwrap().decrypt(&mut eih);
    let expected_hash = blake3::hash(&psk2());
    for j in 0..16 {
        assert_eq!(eih[j], expected_hash.as_bytes()[j] ^ plain_header[j]);
    }

    // Body opens with SessionKey(encryption psk, session_id).
    let mut material = psk2();
    material.extend_from_slice(&plain_header[..8]);
    let subkey = &blake3::derive_key("shadowsocks 2022 session subkey", &material)[..16];
    let cipher = AeadCipher::new("2022-blake3-aes-128-gcm", subkey).unwrap();
    let body = cipher.open(&plain_header[4..16], &packet[32..]).unwrap();
    assert_eq!(body[0], HEADER_TYPE_CLIENT);
}

#[test]
fn test_udp_2022_chacha_roundtrip() {
    let psk_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let method = Ss2022Method::new("2022-blake3-chacha20-poly1305", psk_b64).unwrap();
    let mut session = Ss2022UdpSession::new(method).unwrap();
    let (socks, target) = udp_target();
    let payload = b"quic payload";

    let packet = session.seal_packet(&socks, target.port(), payload).unwrap();
    assert!(packet.len() > UDP_XNONCE_SIZE + TAG_LEN);

    // Server-side parse: nonce || XChaCha20-Poly1305(psk)(body).
    let psk = psk32();
    let server_cipher = AeadCipher::new_xchacha20(&psk).unwrap();
    let (nonce, ct) = packet.split_at(UDP_XNONCE_SIZE);
    let body = server_cipher.open(nonce, ct).unwrap();
    let client_session_id = u64::from_be_bytes(body[..8].try_into().unwrap());
    let client_packet_id = u64::from_be_bytes(body[8..16].try_into().unwrap());
    assert_eq!(client_packet_id, 0);
    assert_eq!(body[16], HEADER_TYPE_CLIENT);
    let padding_len = u16::from_be_bytes([body[25], body[26]]) as usize;
    let rest = &body[27 + padding_len..];
    let skip = addr_len(rest);
    assert_eq!(&rest[skip..], payload);

    let response = server_seal_udp(
        &Ss2022Method::new("2022-blake3-chacha20-poly1305", psk_b64).unwrap(),
        client_session_id,
        0xcafe,
        0,
        unix_timestamp(),
        &socks,
        b"quic response",
    );

    let opened = session.open_packet(&response).unwrap();
    assert_eq!(opened.payload(), b"quic response");
    assert!(session.open_packet(&response).is_err()); // replay
}

#[test]
fn test_udp_2022_server_session_replay_and_rotation() {
    let methods = [
        (
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
        (
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
    ];
    let (socks, _) = udp_target();
    let now = 1_700_000_000;

    for (method_name, password) in methods {
        let mut session =
            Ss2022UdpSession::new(Ss2022Method::new(method_name, password).unwrap()).unwrap();
        let server_method = Ss2022Method::new(method_name, password).unwrap();
        let client_session_id = session.session_id;
        let packet = |server_session_id: u64, packet_id: u64, timestamp: u64, payload: &[u8]| {
            server_seal_udp(
                &server_method,
                client_session_id,
                server_session_id,
                packet_id,
                timestamp,
                &socks,
                payload,
            )
        };

        let a0 = packet(0xa, 0, now, b"a0");
        assert_eq!(session.open_packet_at(&a0, now).unwrap().payload(), b"a0");
        let b0 = packet(0xb, 0, now, b"b0");
        assert_eq!(session.open_packet_at(&b0, now).unwrap().payload(), b"b0");
        assert!(session.open_packet_at(&a0, now).is_err());

        let a1 = packet(0xa, 1, now + 10, b"a1");
        assert_eq!(
            session.open_packet_at(&a1, now + 10).unwrap().payload(),
            b"a1"
        );
        let c0 = packet(0xc, 0, now + 69, b"c0");
        assert!(session.open_packet_at(&c0, now + 69).is_err());
        let c0 = packet(0xc, 0, now + 70, b"c0");
        assert_eq!(
            session.open_packet_at(&c0, now + 70).unwrap().payload(),
            b"c0"
        );
    }
}

#[test]
fn test_udp_2022_failed_server_packet_does_not_mutate_replay_state() {
    let methods = [
        (
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
        (
            "2022-blake3-chacha20-poly1305",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ),
    ];
    let (socks, _) = udp_target();
    let now = 1_700_000_000;

    for (method_name, password) in methods {
        for corrupt_ciphertext in [true, false] {
            let mut session =
                Ss2022UdpSession::new(Ss2022Method::new(method_name, password).unwrap()).unwrap();
            let server_method = Ss2022Method::new(method_name, password).unwrap();
            let client_session_id = session.session_id;
            let packet = |client_id, server_id, packet_id, payload| {
                server_seal_udp(
                    &server_method,
                    client_id,
                    server_id,
                    packet_id,
                    now,
                    &socks,
                    payload,
                )
            };

            let a0 = packet(client_session_id, 0xa, 0, b"a0");
            assert_eq!(session.open_packet_at(&a0, now).unwrap().payload(), b"a0");

            let failed_client_id = if corrupt_ciphertext {
                client_session_id
            } else {
                client_session_id ^ 1
            };
            let mut failed_b0 = packet(failed_client_id, 0xb, 0, b"b0");
            if corrupt_ciphertext {
                *failed_b0.last_mut().unwrap() ^= 1;
            }
            assert!(session.open_packet_at(&failed_b0, now).is_err());

            let c0 = packet(client_session_id, 0xc, 0, b"c0");
            assert_eq!(session.open_packet_at(&c0, now).unwrap().payload(), b"c0");
            assert!(session.open_packet_at(&a0, now).is_err());
            let a1 = packet(client_session_id, 0xa, 1, b"a1");
            assert_eq!(session.open_packet_at(&a1, now).unwrap().payload(), b"a1");
        }
    }
}

/// Mock Shadowsocks 2022 server: parses the request (including EIH),
/// then echoes every received chunk payload back inside a proper
/// response stream.
async fn mock_2022_server(
    listener: tokio::net::TcpListener,
    password: &'static str,
    method_name: &'static str,
) {
    let method = Ss2022Method::new(method_name, password).unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let (mut rd, mut wr) = stream.into_split();

    // Salt + EIH.
    let mut salt = vec![0u8; method.key_len];
    rd.read_exact(&mut salt).await.unwrap();
    let eih_len = (method.psks.len() - 1) * 16;
    let mut eihs = vec![0u8; eih_len];
    rd.read_exact(&mut eihs).await.unwrap();
    for (i, chunk) in eihs.chunks(16).enumerate() {
        let mut material = method.psks[i].clone();
        material.extend_from_slice(&salt);
        let identity_subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &material);
        let mut block_data: [u8; 16] = chunk.try_into().unwrap();
        AesBlock::new(&identity_subkey[..method.key_len])
            .unwrap()
            .decrypt(&mut block_data);
        assert_eq!(block_data, method.psk_hashes[i], "EIH {} mismatch", i);
    }

    // Fixed + variable request headers.
    let subkey = method.session_subkey(&salt);
    let cipher = method.aead(&subkey).unwrap();
    let mut nonce = vec![0u8; NONCE_LEN];
    let mut fixed = vec![0u8; 11 + TAG_LEN];
    rd.read_exact(&mut fixed).await.unwrap();
    let fixed = cipher.open(&nonce, &fixed).unwrap();
    increment_nonce(&mut nonce);
    assert_eq!(fixed[0], HEADER_TYPE_CLIENT);
    let ts = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
    assert!(unix_timestamp().abs_diff(ts) <= 30);
    let var_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
    let mut var = vec![0u8; var_len + TAG_LEN];
    rd.read_exact(&mut var).await.unwrap();
    let var = cipher.open(&nonce, &var).unwrap();
    increment_nonce(&mut nonce);
    let addr_len = addr_len(&var);
    let padding_len = u16::from_be_bytes([var[addr_len], var[addr_len + 1]]) as usize;
    assert!(padding_len > 0, "padding must be present without payload");
    assert_eq!(var.len(), addr_len + 2 + padding_len);

    // Response direction state.
    let mut resp_salt = vec![0u8; method.key_len];
    rand::rng().fill_bytes(&mut resp_salt);
    let resp_subkey = method.session_subkey(&resp_salt);
    let resp_cipher = method.aead(&resp_subkey).unwrap();
    let mut resp_nonce = vec![0u8; NONCE_LEN];
    let mut response_started = false;

    // Echo loop: read chunk payloads, echo them back.
    let mut len_buf = vec![0u8; 2 + TAG_LEN];
    loop {
        if rd.read_exact(&mut len_buf).await.is_err() {
            return;
        }
        let len_plain = cipher.open(&nonce, &len_buf).unwrap();
        increment_nonce(&mut nonce);
        let len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        let mut payload = vec![0u8; len + TAG_LEN];
        rd.read_exact(&mut payload).await.unwrap();
        let plain = cipher.open(&nonce, &payload).unwrap();
        increment_nonce(&mut nonce);

        if !response_started {
            response_started = true;
            // Fixed response header (doubles as first length chunk).
            let mut header = Vec::new();
            header.extend_from_slice(&resp_salt);
            let mut fixed = Vec::new();
            fixed.push(HEADER_TYPE_SERVER);
            fixed.extend_from_slice(&unix_timestamp().to_be_bytes());
            fixed.extend_from_slice(&salt); // echo request salt
            fixed.extend_from_slice(&(plain.len() as u16).to_be_bytes());
            header.extend_from_slice(&resp_cipher.seal(&resp_nonce, &fixed).unwrap());
            increment_nonce(&mut resp_nonce);
            header.extend_from_slice(&resp_cipher.seal(&resp_nonce, &plain).unwrap());
            increment_nonce(&mut resp_nonce);
            wr.write_all(&header).await.unwrap();
        } else {
            let mut chunk = Vec::new();
            chunk.extend_from_slice(
                &resp_cipher
                    .seal(&resp_nonce, &(plain.len() as u16).to_be_bytes())
                    .unwrap(),
            );
            increment_nonce(&mut resp_nonce);
            chunk.extend_from_slice(&resp_cipher.seal(&resp_nonce, &plain).unwrap());
            increment_nonce(&mut resp_nonce);
            wr.write_all(&chunk).await.unwrap();
        }
    }
}

async fn tcp_roundtrip(method_name: &'static str, password: &'static str) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(mock_2022_server(listener, password, method_name));

    let node = Node {
        name: "test-ss2022".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some(method_name.to_string()),
                password: Some(password.to_string()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let stream = handler
        .dial(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();
    let mut stream = stream.stream;

    // First exchange (drives the response fixed-header path).
    stream.write_all(b"hello ss2022").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello ss2022");

    // Second exchange (drives the regular chunk path).
    stream.write_all(b"second message").await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"second message");
}

#[tokio::test]
async fn test_tcp_2022_aes_128_roundtrip() {
    tcp_roundtrip("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw==").await;
}

#[tokio::test]
async fn test_tcp_2022_aes_256_roundtrip() {
    tcp_roundtrip(
        "2022-blake3-aes-256-gcm",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    )
    .await;
}

#[tokio::test]
async fn test_tcp_2022_chacha_roundtrip() {
    tcp_roundtrip(
        "2022-blake3-chacha20-poly1305",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    )
    .await;
}

#[tokio::test]
async fn test_tcp_2022_eih_roundtrip() {
    // Multi-psk: mock server asserts the EIH blocks decrypt correctly.
    tcp_roundtrip(
        "2022-blake3-aes-128-gcm",
        "AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==",
    )
    .await;
}

/// End-to-end UDP test: mock Shadowsocks 2022 server, real
/// `dial_udp_transport`, payload exchange through the framed transport.
#[tokio::test]
async fn test_dial_udp_2022_end_to_end() {
    let psk_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_method = Ss2022Method::new("2022-blake3-aes-256-gcm", psk_b64).unwrap();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let socks = crate::proxy::addr::encode_address(target, None).unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        let mut server_packet_id = 0u64;
        loop {
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            let (client_session_id, _pid, payload) = server_open_aes(&server_method, &buf[..n]);
            let reply: Vec<u8> = payload.iter().map(|b| b.to_ascii_uppercase()).collect();
            let packet = server_seal_udp(
                &server_method,
                client_session_id,
                0xbeef,
                server_packet_id,
                unix_timestamp(),
                &socks,
                &reply,
            );
            server_packet_id += 1;
            server.send_to(&packet, src).await.unwrap();
        }
    });

    let node = Node {
        name: "test-ss2022-udp".into(),
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        outbound: honk_config::node::OutboundConfig::Shadowsocks(
            honk_config::node::ShadowsocksConfig {
                encryption: Some("2022-blake3-aes-256-gcm".into()),
                password: Some(psk_b64.to_string()),
                ..Default::default()
            },
        ),
        ..Default::default()
    };
    let handler = ShadowsocksHandler::new();
    let transport = handler
        .dial_udp_transport(&node, target, None, std::time::Duration::from_secs(3))
        .await
        .unwrap();

    transport.send_packet(b"quic data").await.unwrap();
    let mut buf = [0u8; 9];
    let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], b"QUIC DATA");

    // Second datagram on the same session (packet id continuity).
    transport.send_packet(b"more data").await.unwrap();
    let (n, _src) = transport.recv_packet(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"MORE DATA");
}

/// Independent SIP022 UDP server-side wire peer for the shared-association
/// tests; it frames both directions without the production session codec.
struct Peer2022 {
    method: &'static str,
    chacha: bool,
    psk: Vec<u8>,
}

/// One client datagram as the server sees it.
struct ClientPacket {
    session_id: u64,
    packet_id: u64,
    /// `address | payload`, padding already skipped.
    rest: Vec<u8>,
}

const METHODS_2022: [(&str, &str); 3] = [
    ("2022-blake3-aes-128-gcm", "AAECAwQFBgcICQoLDA0ODw=="),
    (
        "2022-blake3-aes-256-gcm",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    ),
    (
        "2022-blake3-chacha20-poly1305",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    ),
];

impl Peer2022 {
    fn new(method: &'static str) -> Self {
        Self {
            method,
            chacha: method.contains("chacha"),
            psk: if method.ends_with("128-gcm") {
                psk1()
            } else {
                psk32()
            },
        }
    }

    fn aes_ecb(&self) -> AesBlock {
        AesBlock::new(&self.psk).unwrap()
    }

    fn session_cipher(&self, session_id: &[u8]) -> AeadCipher {
        let mut material = self.psk.clone();
        material.extend_from_slice(session_id);
        let key = blake3::derive_key("shadowsocks 2022 session subkey", &material);
        AeadCipher::new(self.method, &key[..self.psk.len()]).unwrap()
    }

    fn open(&self, packet: &[u8]) -> ClientPacket {
        let (session_id, packet_id, body);
        if self.chacha {
            let plain = AeadCipher::new_xchacha20(&self.psk)
                .unwrap()
                .open(&packet[..24], &packet[24..])
                .unwrap();
            session_id = u64::from_be_bytes(plain[..8].try_into().unwrap());
            packet_id = u64::from_be_bytes(plain[8..16].try_into().unwrap());
            body = plain[16..].to_vec();
        } else {
            let mut header: [u8; 16] = packet[..16].try_into().unwrap();
            self.aes_ecb().decrypt(&mut header);
            session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
            packet_id = u64::from_be_bytes(header[8..].try_into().unwrap());
            body = self
                .session_cipher(&header[..8])
                .open(&header[4..], &packet[16..])
                .unwrap();
        }
        assert_eq!(body[0], 0, "client header type");
        let padding = u16::from_be_bytes([body[9], body[10]]) as usize;
        ClientPacket {
            session_id,
            packet_id,
            rest: body[11 + padding..].to_vec(),
        }
    }

    /// A server datagram with explicit header fields so tests can forge
    /// replays, stale timestamps and wrong sessions.
    #[allow(clippy::too_many_arguments)]
    fn seal_raw(
        &self,
        header_type: u8,
        timestamp: u64,
        client_session: u64,
        server_session: u64,
        packet_id: u64,
        padding: &[u8],
        rest: &[u8],
    ) -> Vec<u8> {
        let mut ids = [0u8; 16];
        ids[..8].copy_from_slice(&server_session.to_be_bytes());
        ids[8..].copy_from_slice(&packet_id.to_be_bytes());
        let mut body = Vec::new();
        if self.chacha {
            body.extend_from_slice(&ids);
        }
        body.push(header_type);
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.extend_from_slice(&client_session.to_be_bytes());
        body.extend_from_slice(&(padding.len() as u16).to_be_bytes());
        body.extend_from_slice(padding);
        body.extend_from_slice(rest);
        if self.chacha {
            let mut nonce = [0u8; 24];
            rand::rng().fill_bytes(&mut nonce);
            let mut packet = nonce.to_vec();
            packet.extend_from_slice(
                &AeadCipher::new_xchacha20(&self.psk)
                    .unwrap()
                    .seal(&nonce, &body)
                    .unwrap(),
            );
            return packet;
        }
        let mut packet = ids;
        self.aes_ecb().encrypt(&mut packet);
        let mut packet = packet.to_vec();
        packet.extend_from_slice(
            &self
                .session_cipher(&ids[..8])
                .seal(&ids[4..], &body)
                .unwrap(),
        );
        packet
    }

    fn seal(
        &self,
        client: u64,
        server: u64,
        packet_id: u64,
        addr: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        self.seal_raw(
            1,
            unix_timestamp(),
            client,
            server,
            packet_id,
            &[],
            &[addr, payload].concat(),
        )
    }

    /// Fixed bytes a client datagram carries around its payload, for an
    /// IPv4 destination on a port that draws no padding.
    fn client_overhead(&self) -> usize {
        let framing = if self.chacha { 24 + 16 } else { 16 };
        framing + 1 + 8 + 2 + 7 + TAG_LEN
    }

    fn server_overhead(&self) -> usize {
        let framing = if self.chacha { 24 + 16 } else { 16 };
        framing + 1 + 8 + 8 + 2 + 7 + TAG_LEN
    }
}

fn addr_v4_v6(peer: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match peer {
        SocketAddr::V4(v4) => {
            out.push(1);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(4);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&peer.port().to_be_bytes());
    out
}

fn addr_domain(domain: &str, port: u16) -> Vec<u8> {
    let mut out = vec![3, domain.len() as u8];
    out.extend_from_slice(domain.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

const STEP_2022: std::time::Duration = std::time::Duration::from_secs(2);
const SERVER_SESSION: u64 = 0x5e55_1011;

struct Shared2022 {
    server: tokio::net::UdpSocket,
    peer: Peer2022,
    transport: std::sync::Arc<dyn crate::proxy::MultiTargetTransport>,
}

impl Shared2022 {
    async fn new(
        (method, password): (&'static str, &str),
        target: SocketAddr,
        domain: Option<&str>,
    ) -> Self {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let node = Node {
            name: "test-ss2022-shared".into(),
            address: addr.ip().to_string(),
            port: addr.port(),
            outbound: honk_config::node::OutboundConfig::Shadowsocks(
                honk_config::node::ShadowsocksConfig {
                    encryption: Some(method.into()),
                    password: Some(password.into()),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        let transport = ShadowsocksHandler::prepare_udp_source(&node, target, domain, STEP_2022)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        Self {
            server,
            peer: Peer2022::new(method),
            transport,
        }
    }

    async fn send(&self, to: SocketAddr, payload: &[u8]) {
        self.transport
            .send_to(to, None, payload, false, None)
            .await
            .unwrap();
    }

    async fn server_recv(&self) -> (SocketAddr, ClientPacket) {
        let mut buf = vec![0u8; 65536];
        let (n, from) = tokio::time::timeout(STEP_2022, self.server.recv_from(&mut buf))
            .await
            .expect("server datagram")
            .unwrap();
        (from, self.peer.open(&buf[..n]))
    }

    async fn forward(&self, client: SocketAddr, packet: Vec<u8>) {
        self.server.send_to(&packet, client).await.unwrap();
    }

    async fn client_recv(&self) -> (Vec<u8>, SocketAddr) {
        let mut buf = vec![0u8; 65536];
        let (n, from) = tokio::time::timeout(STEP_2022, self.transport.recv_packet(&mut buf))
            .await
            .expect("client datagram")
            .unwrap();
        (buf[..n].to_vec(), from)
    }
}

/// Every destination of a client source rides one SS2022 session: one
/// client session id, one strictly increasing packet counter, one server
/// replay window; replies return the authenticated inner peer.
#[tokio::test]
async fn udp_2022_one_session_serves_every_destination() {
    for method in METHODS_2022 {
        let a: SocketAddr = "198.51.100.1:5300".parse().unwrap();
        let b: SocketAddr = "[2001:db8::2]:5353".parse().unwrap();
        let c: SocketAddr = "203.0.113.9:4000".parse().unwrap();
        let c6: SocketAddr = "[2001:db8::9]:9".parse().unwrap();
        let shared = Shared2022::new(method, a, None).await;

        shared.send(a, b"to-a").await;
        shared.send(b, b"to-b").await;
        shared.send(a, b"").await;
        shared.send(b, b"to-b2").await;
        let mut first = None;
        for (index, (to, payload)) in [
            (a, &b"to-a"[..]),
            (b, &b"to-b"[..]),
            (a, &b""[..]),
            (b, &b"to-b2"[..]),
        ]
        .into_iter()
        .enumerate()
        {
            let (from, packet) = shared.server_recv().await;
            let (session, outer) = *first.get_or_insert((packet.session_id, from));
            assert_eq!(packet.session_id, session, "{}: one session id", method.0);
            assert_eq!(from, outer, "{}: one outer source", method.0);
            assert_eq!(packet.packet_id, index as u64, "{}: counter", method.0);
            assert_eq!(packet.rest, [addr_v4_v6(to), payload.to_vec()].concat());
        }
        let (session, client) = first.unwrap();

        // Unsolicited peers, then the contacted ones, share one server window.
        let reply = |pid: u64, addr: &[u8], payload: &[u8]| {
            shared
                .peer
                .seal(session, SERVER_SESSION, pid, addr, payload)
        };
        shared
            .forward(client, reply(0, &addr_v4_v6(c), b"from-c"))
            .await;
        assert_eq!(shared.client_recv().await, (b"from-c".to_vec(), c));
        shared
            .forward(client, reply(1, &addr_v4_v6(c6), b"from-c6"))
            .await;
        assert_eq!(shared.client_recv().await, (b"from-c6".to_vec(), c6));
        shared
            .forward(client, reply(2, &addr_v4_v6(b), b"from-b"))
            .await;
        assert_eq!(shared.client_recv().await, (b"from-b".to_vec(), b));
        shared.forward(client, reply(3, &addr_v4_v6(a), b"")).await;
        assert_eq!(shared.client_recv().await, (Vec::new(), a));

        // A packet id already used for another destination is a replay.
        shared
            .forward(client, reply(3, &addr_v4_v6(b), b"dup"))
            .await;
        shared
            .forward(client, reply(2, &addr_v4_v6(a), b"dup"))
            .await;
        let mapped = vec![
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 7, 0x1f, 0x90,
        ];
        shared.forward(client, reply(4, &mapped, b"mapped")).await;
        let expected: SocketAddr = "192.0.2.7:8080".parse().unwrap();
        assert_eq!(shared.client_recv().await, (b"mapped".to_vec(), expected));
    }
}

/// A domain source is the dialed domain and port or it is dropped.
#[tokio::test]
async fn udp_2022_domain_source_projects_only_the_dialed_name() {
    for method in METHODS_2022 {
        let a: SocketAddr = "198.51.100.1:5300".parse().unwrap();
        let c: SocketAddr = "203.0.113.9:4000".parse().unwrap();
        let shared = Shared2022::new(method, a, Some("Example.COM")).await;
        shared.transport.send_packet(b"d").await.unwrap();
        shared
            .transport
            .send_to(a, Some("other.example"), b"o", false, None)
            .await
            .unwrap();
        let (client, first) = shared.server_recv().await;
        assert_eq!(
            first.rest,
            [addr_domain("Example.COM", 5300), b"d".to_vec()].concat()
        );
        let (_, second) = shared.server_recv().await;
        assert_eq!(
            second.rest,
            [addr_domain("other.example", 5300), b"o".to_vec()].concat()
        );

        let session = first.session_id;
        let reply = |pid: u64, addr: &[u8], payload: &[u8]| {
            shared
                .peer
                .seal(session, SERVER_SESSION, pid, addr, payload)
        };
        shared
            .forward(client, reply(0, &addr_domain("other.example", 5300), b"x"))
            .await;
        shared
            .forward(client, reply(1, &addr_domain("example.com", 5301), b"x"))
            .await;
        shared
            .forward(
                client,
                reply(2, &addr_domain("example.com", 5300), b"named"),
            )
            .await;
        assert_eq!(shared.client_recv().await, (b"named".to_vec(), a));
        shared
            .forward(client, reply(3, &addr_domain("other.example", 5300), b"x"))
            .await;
        shared
            .forward(client, reply(4, &addr_v4_v6(c), b"after"))
            .await;
        assert_eq!(shared.client_recv().await, (b"after".to_vec(), c));
    }
}

/// Bad frames each drop only their datagram, and a frame whose address fails
/// to decode leaves its packet id unspent.
#[tokio::test]
async fn udp_2022_bad_frames_drop_only_the_datagram() {
    for method in METHODS_2022 {
        let a: SocketAddr = "198.51.100.1:5300".parse().unwrap();
        let shared = Shared2022::new(method, a, None).await;
        shared.send(a, b"hello").await;
        let (client, first) = shared.server_recv().await;
        let session = first.session_id;
        let now = unix_timestamp();
        let good = [addr_v4_v6(a), b"genuine".to_vec()].concat();
        let seal = |header, ts, sid, pid, padding: &[u8], rest: &[u8]| {
            shared
                .peer
                .seal_raw(header, ts, sid, SERVER_SESSION, pid, padding, rest)
        };

        let frames = [
            vec![0u8; 8],
            seal(0, now, session, 0, &[], &good),
            seal(1, now - 100, session, 0, &[], &good),
            seal(1, now, session ^ 1, 0, &[], &good),
            // No address at all.
            seal(1, now, session, 0, &[], &[]),
            seal(1, now, session, 0, &[], &[5, 1, 2, 3, 4, 5, 6, 7]),
            seal(1, now, session, 0, &[], &[3, 0, 0, 53]),
            seal(1, now, session, 0, &[], &[3, 2, 0xff, 0xfe, 0, 53, 1]),
            {
                let mut frame = seal(1, now, session, 0, &[], &good);
                *frame.last_mut().unwrap() ^= 1;
                frame
            },
        ];
        for frame in frames {
            shared.forward(client, frame).await;
        }
        // Packet id 0 was never spent by any of the failures above.
        shared
            .forward(client, seal(1, now, session, 0, &[], &good))
            .await;
        assert_eq!(
            shared.client_recv().await,
            (b"genuine".to_vec(), a),
            "{}",
            method.0
        );
    }
}

/// The largest datagram that fits one UDP packet crosses both ways; one
/// byte more is refused without hurting the session.
#[tokio::test]
async fn udp_2022_max_size_boundary() {
    for method in METHODS_2022 {
        let a: SocketAddr = "198.51.100.1:5300".parse().unwrap();
        let shared = Shared2022::new(method, a, None).await;
        let up = vec![0x5a; 65507 - shared.peer.client_overhead()];
        shared.send(a, &up).await;
        let (client, packet) = shared.server_recv().await;
        assert_eq!(packet.rest[7..], up[..]);

        let down = vec![0xa5; 65507 - shared.peer.server_overhead()];
        shared
            .forward(
                client,
                shared
                    .peer
                    .seal(packet.session_id, SERVER_SESSION, 0, &addr_v4_v6(a), &down),
            )
            .await;
        assert_eq!(shared.client_recv().await, (down, a));

        let error = shared
            .transport
            .send_to(a, None, &vec![0; up.len() + 1], false, None)
            .await
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EMSGSIZE));
        shared.send(a, b"alive").await;
        let (_, alive) = shared.server_recv().await;
        assert_eq!(alive.rest[7..], b"alive"[..]);
        assert_eq!(alive.packet_id, 2, "a refused send still spends a counter");
    }
}
