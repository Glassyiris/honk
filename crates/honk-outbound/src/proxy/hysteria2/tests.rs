use super::*;
use crate::quic::testutil;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_PASSWORD: &str = "hy2-test-password";

fn test_node(port: u16, password: &str) -> Node {
    Node {
        name: "hy2-test".to_string(),
        protocol: NodeProtocol::Hysteria2,
        host: "127.0.0.1".to_string(),
        address: format!("127.0.0.1:{port}"),
        port,
        hy2_auth: Some(password.to_string()),
        skip_cert_verify: true,
        ..Default::default()
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Huffman-encode per RFC 7541 §5.2 (test-side mirror of the quic-go
/// QPACK encoder; unused in production code, which never Huffman-encodes).
fn huffman_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        let (code, len) = HUFFMAN_TABLE[b as usize];
        acc = (acc << len) | u64::from(code);
        nbits += u32::from(len);
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if nbits > 0 {
        out.push(((acc << (8 - nbits)) | ((1u64 << (8 - nbits)) - 1)) as u8);
    }
    out
}

/// Encode a field section byte-for-byte like quic-go's QPACK encoder
/// (`qpack/encoder.go`): exact static matches, then static name
/// references, then Huffman-coded literal names/values. Covers the static
/// entries the test server emits.
fn qpack_test_encode(fields: &[(&str, &str)]) -> Vec<u8> {
    const FULL: &[(&str, &str, u64)] = &[
        (":path", "/", 1),
        ("content-length", "0", 4),
        (":method", "POST", 20),
        (":scheme", "https", 23),
        (":status", "103", 24),
        (":status", "200", 25),
        (":status", "304", 26),
        (":status", "404", 27),
        (":status", "503", 28),
    ];
    const NAME: &[(&str, u64)] = &[
        (":authority", 0),
        (":path", 1),
        ("content-length", 4),
        (":status", 24),
        ("user-agent", 95),
    ];
    let mut out = vec![0x00, 0x00];
    for &(name, value) in fields {
        if let Some(&(_, _, idx)) = FULL.iter().find(|&&(n, v, _)| n == name && v == value) {
            write_prefixed_int(&mut out, 6, 0xc0, idx);
            continue;
        }
        if let Some(&(_, idx)) = NAME.iter().find(|&&(n, _)| n == name) {
            write_prefixed_int(&mut out, 4, 0x50, idx);
            let encoded = huffman_encode(value.as_bytes());
            write_prefixed_int(&mut out, 7, 0x80, encoded.len() as u64);
            out.extend_from_slice(&encoded);
            continue;
        }
        let name_encoded = huffman_encode(name.as_bytes());
        write_prefixed_int(&mut out, 3, 0x28, name_encoded.len() as u64);
        out.extend_from_slice(&name_encoded);
        let value_encoded = huffman_encode(value.as_bytes());
        write_prefixed_int(&mut out, 7, 0x80, value_encoded.len() as u64);
        out.extend_from_slice(&value_encoded);
    }
    out
}

/// Minimal hysteria2 server: H3 auth exchange (password check, 233/404),
/// TCP 0x401 streams answered OK and echoed, UDP datagrams echoed
/// verbatim. Responses are encoded with the same QPACK forms (Huffman
/// included) that quic-go produces.
async fn start_server(password: &'static str) -> SocketAddr {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                handle_connection(conn, password).await;
            });
        }
    });
    addr
}

/// Same server behind a salamander-obfuscated socket.
async fn start_obfs_server(password: &'static str, obfs_password: &'static [u8]) -> SocketAddr {
    let config = testutil::server_config(&[b"h3"], true).unwrap();
    let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    std_socket.set_nonblocking(true).unwrap();
    let socket = Arc::new(Hy2UdpSocket {
        socket: Arc::new(tokio::net::UdpSocket::from_std(std_socket).unwrap()),
        obfs: Some(Arc::from(obfs_password)),
        hop: Mutex::new(None),
    });
    let runtime = quinn::default_runtime().unwrap();
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                handle_connection(conn, password).await;
            });
        }
    });
    addr
}

async fn handle_connection(conn: quinn::Connection, password: &'static str) {
    let authenticated = Arc::new(AtomicBool::new(false));
    // Uni streams: the client preface (control + QPACK encoder/decoder).
    // Drain them; their content is not needed by this minimal server.
    let uni_conn = conn.clone();
    tokio::spawn(async move {
        loop {
            let Ok(mut recv) = uni_conn.accept_uni().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while matches!(recv.read(&mut buf).await, Ok(Some(_))) {}
            });
        }
    });
    // Bi streams: auth requests and TCP 0x401 streams.
    let bi_conn = conn.clone();
    let bi_auth = Arc::clone(&authenticated);
    tokio::spawn(async move {
        loop {
            let Ok((send, recv)) = bi_conn.accept_bi().await else {
                break;
            };
            let auth = Arc::clone(&bi_auth);
            tokio::spawn(async move {
                handle_server_stream(send, recv, auth, password).await;
            });
        }
    });
    // Datagrams: echo UDP messages back verbatim.
    loop {
        let Ok(data) = conn.read_datagram().await else {
            break;
        };
        let _ = conn.send_datagram(data);
    }
}

async fn handle_server_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    authenticated: Arc<AtomicBool>,
    password: &str,
) {
    let Ok(frame_type) = read_varint_stream(&mut recv).await else {
        return;
    };
    match frame_type {
        H3_FRAME_HEADERS => {
            handle_auth_request(&mut send, &mut recv, authenticated, password).await
        }
        FRAME_TYPE_TCP_REQUEST if authenticated.load(Ordering::Relaxed) => {
            handle_tcp_request(&mut send, &mut recv).await
        }
        _ => {}
    }
}

async fn handle_auth_request(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    authenticated: Arc<AtomicBool>,
    password: &str,
) {
    let Ok(len) = read_varint_stream(recv).await else {
        return;
    };
    if len > MAX_FIELD_SECTION {
        return;
    }
    let mut payload = vec![0u8; len as usize];
    if read_exact(recv, &mut payload).await.is_err() {
        return;
    }
    let Ok(fields) = qpack_decode_field_section(&payload) else {
        return;
    };
    let get = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    let authed = get(":method") == Some("POST")
        && get(":authority") == Some(URL_HOST)
        && get(":path") == Some(URL_PATH)
        && get(HEADER_AUTH) == Some(password);
    let (status, udp_enabled) = if authed {
        (STATUS_AUTH_OK, true)
    } else {
        (404u16, false)
    };
    if authed {
        authenticated.store(true, Ordering::Relaxed);
    }
    let padding = random_padding(AUTH_PADDING_MIN, AUTH_PADDING_MAX);
    let status_str = status.to_string();
    let section = qpack_test_encode(&[
        (":status", status_str.as_str()),
        (HEADER_UDP, if udp_enabled { "true" } else { "false" }),
        (HEADER_CC_RX, "0"),
        (HEADER_PADDING, padding.as_str()),
        ("content-length", "0"),
    ]);
    if send.write_all(&h3_headers_frame(&section)).await.is_err() {
        return;
    }
    let _ = send.finish();
}

async fn handle_tcp_request(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream) {
    // ReadTCPRequest: address vstring + padding (`protocol/proxy.go:39-67`).
    let Ok(addr_len) = read_varint_stream(recv).await else {
        return;
    };
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        return;
    }
    let mut addr = vec![0u8; addr_len as usize];
    if read_exact(recv, &mut addr).await.is_err() {
        return;
    }
    let Ok(padding_len) = read_varint_stream(recv).await else {
        return;
    };
    if padding_len > MAX_PADDING_LENGTH {
        return;
    }
    if skip_bytes(recv, padding_len).await.is_err() {
        return;
    }
    // WriteTCPResponse(ok) with server-side padding (128..1024 in sing).
    let padding = random_padding(128, 1024);
    let mut resp = vec![0u8];
    write_varint(&mut resp, 0);
    write_varint(&mut resp, padding.len() as u64);
    resp.extend_from_slice(padding.as_bytes());
    if send.write_all(&resp).await.is_err() {
        return;
    }
    // Echo the stream payload.
    let mut buf = [0u8; 8192];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                if send.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
            _ => return,
        }
    }
}

#[test]
fn test_varint_boundaries() {
    let mut out = Vec::new();
    write_varint(&mut out, 0);
    assert_eq!(out, [0x00]);
    out.clear();
    write_varint(&mut out, 63);
    assert_eq!(out, [0x3f]);
    out.clear();
    write_varint(&mut out, 64);
    assert_eq!(out, [0x40, 0x40]);
    out.clear();
    write_varint(&mut out, 16383);
    assert_eq!(out, [0x7f, 0xff]);
    out.clear();
    write_varint(&mut out, 16384);
    assert_eq!(out, [0x80, 0x00, 0x40, 0x00]);
    out.clear();
    // The hysteria2 TCP request frame type must serialize to [0x44, 0x01].
    write_varint(&mut out, FRAME_TYPE_TCP_REQUEST);
    assert_eq!(out, [0x44, 0x01]);
    out.clear();
    write_varint(&mut out, 0xcafe_babe_dead_beef);
    assert_eq!(out.len(), 8);
    assert_eq!(out[0] & 0xc0, 0xc0);
}

#[test]
fn test_prefixed_int_roundtrip() {
    for value in [0u64, 10, 62, 63, 64, 1000, 65536, 1 << 20] {
        let mut out = Vec::new();
        write_prefixed_int(&mut out, 6, 0xc0, value);
        let mut cursor = &out[..];
        let first = cursor[0];
        cursor = &cursor[1..];
        assert_eq!(read_prefixed_int(&mut cursor, first, 6).unwrap(), value);
        assert!(cursor.is_empty());
    }
    // 3-bit prefix with continuation (as used for literal header names).
    let mut out = Vec::new();
    write_prefixed_int(&mut out, 3, 0x20, 13);
    let first = out[0];
    let mut cursor = &out[1..];
    assert_eq!(read_prefixed_int(&mut cursor, first, 3).unwrap(), 13);
}

#[test]
fn test_huffman_rfc_vector() {
    // RFC 7541 Appendix C.4.1: "www.example.com".
    let encoded = unhex("f1e3c2e5f23a6ba0ab90f4ff");
    assert_eq!(
        huffman_decode(&encoded).as_deref(),
        Some(b"www.example.com".as_slice())
    );
    assert_eq!(huffman_encode(b"www.example.com"), encoded);
}

#[test]
fn test_huffman_roundtrip() {
    for s in [
        "hysteria",
        "hysteria-auth",
        "s3cret-password!!",
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "true",
        "233",
        "/auth",
    ] {
        let encoded = huffman_encode(s.as_bytes());
        assert_eq!(huffman_decode(&encoded).as_deref(), Some(s.as_bytes()));
    }
}

/// Golden vectors produced by the real quic-go qpack encoder (see
/// `sing-box/vendor/github.com/quic-go/qpack/encoder.go`).
const GOLDEN_AUTH_OK_RESPONSE: &str = "00005f0983132cff2f029fd2125b0c35ad92bf834d96972f039fd2125b0c358845acf381072f059fd2125b0c35ab1c921aa9bf9b1c6490b2cd39ba75a29a8f5f6b109b7bf8f3ebd802265a6dc75e7fc4";
const GOLDEN_AUTH_REJECT_RESPONSE: &str = "0000db54820bff";
const GOLDEN_AUTH_REQUEST: &str = "000050869fd2125b0c3fd451846076a67fd72f029fd2125b0c35876a678b4324b0a95ab1a11e0f649f2f039fd2125b0c358845acf381072f059fd2125b0c35ab1c921aa9bf8986edebf830e2c7932fc45f5085ed6988b4c7";

#[test]
fn test_qpack_decode_golden_auth_ok_response() {
    let fields = qpack_decode_field_section(&unhex(GOLDEN_AUTH_OK_RESPONSE)).unwrap();
    let get = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(get(":status"), Some("233"));
    assert_eq!(get("hysteria-udp"), Some("true"));
    assert_eq!(get("hysteria-cc-rx"), Some("0"));
    assert_eq!(
        get("hysteria-padding"),
        Some("abcdefghijklmnopqrstuvwxyz0123456789")
    );
    assert_eq!(get("content-length"), Some("0"));
}

#[test]
fn test_qpack_decode_golden_auth_reject_response() {
    let fields = qpack_decode_field_section(&unhex(GOLDEN_AUTH_REJECT_RESPONSE)).unwrap();
    assert_eq!(
        fields,
        vec![
            (":status".to_string(), "404".to_string()),
            ("content-length".to_string(), "19".to_string()),
        ]
    );
}

#[test]
fn test_qpack_decode_golden_auth_request() {
    let fields = qpack_decode_field_section(&unhex(GOLDEN_AUTH_REQUEST)).unwrap();
    let get = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(get(":authority"), Some("hysteria"));
    assert_eq!(get(":method"), Some("POST"));
    assert_eq!(get(":path"), Some("/auth"));
    assert_eq!(get(":scheme"), Some("https"));
    assert_eq!(get("hysteria-auth"), Some("s3cret-password"));
    assert_eq!(get("hysteria-cc-rx"), Some("0"));
    assert_eq!(get("hysteria-padding"), Some("ABCDEFGHIJ"));
    assert_eq!(get("content-length"), Some("0"));
    assert_eq!(get("user-agent"), Some("quic-go"));
}

/// The test-side encoder must reproduce quic-go's exact bytes for the
/// same field list — this anchors both the Huffman table and the QPACK
/// field-line forms against the reference implementation.
#[test]
fn test_qpack_encode_parity_with_quic_go() {
    let encoded = qpack_test_encode(&[
        (":status", "233"),
        ("hysteria-udp", "true"),
        ("hysteria-cc-rx", "0"),
        ("hysteria-padding", "abcdefghijklmnopqrstuvwxyz0123456789"),
        ("content-length", "0"),
    ]);
    assert_eq!(encoded, unhex(GOLDEN_AUTH_OK_RESPONSE));
}

#[test]
fn test_blake2b256_vectors() {
    // Reference values from Python's hashlib.blake2b(digest_size=32).
    assert_eq!(
        blake2b256(b""),
        unhex("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8").as_slice()
    );
    assert_eq!(
        blake2b256(b"abc"),
        unhex("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319").as_slice()
    );
    // Exactly one full block, and a multi-block input (300 bytes of 0xab).
    assert_eq!(
        blake2b256(&[0xabu8; 128]),
        unhex("e28dbbbacc7cafa062f8c043bf25ec6043bfa25fb32ab91881e09c0a300290d2").as_slice()
    );
    assert_eq!(
        blake2b256(&[0xabu8; 300]),
        unhex("2a5e8e68fa2411e915a353ab9e3f23aea5fa4db80aff0134f82eea790745e7c5").as_slice()
    );
}

#[test]
fn test_salamander_roundtrip() {
    let password = b"obfs-password";
    let data = b"hello salamander";
    let sealed = salamander_seal(password, data);
    assert_eq!(sealed.len(), data.len() + SALAMANDER_SALT_LEN);
    let mut buf = sealed.clone();
    let len = salamander_open(password, &mut buf).unwrap();
    assert_eq!(&buf[..len], data);
    // Wrong password must not reproduce the plaintext.
    let mut bad = sealed;
    let bad_len = salamander_open(b"other-password", &mut bad).unwrap();
    assert_ne!(&bad[..bad_len], data);
    // Malformed (too short) packets are dropped.
    let mut short = [0u8; SALAMANDER_SALT_LEN];
    assert_eq!(salamander_open(password, &mut short), None);
}

#[test]
fn test_udp_message_codec_roundtrip() {
    let pkt = encode_udp_message(0xdead_beef, 42, 0, 1, "8.8.8.8:53", b"payload");
    assert_eq!(&pkt[..4], &[0xde, 0xad, 0xbe, 0xef]);
    let msg = decode_udp_message(&pkt).unwrap();
    assert_eq!(msg.session_id, 0xdead_beef);
    assert_eq!(msg.packet_id, 42);
    assert_eq!(msg.frag_total, 1);
    assert_eq!(msg.frag_id, 0);
    assert_eq!(msg.addr, "8.8.8.8:53");
    assert_eq!(msg.data, b"payload");
}

#[test]
fn test_fragmentation_and_defrag() {
    let data = vec![0xabu8; 3000];
    let frags = fragment_udp_message(1, 99, "8.8.8.8:53", &data, 1200).unwrap();
    assert_eq!(frags.len(), 3);
    assert!(frags.iter().all(|f| f.len() <= 1200));
    // Every fragment repeats the full header (sing parity).
    let mut map: HashMap<u16, DefragBuffer> = HashMap::new();
    let mut out = None;
    for pkt in frags.iter().rev() {
        let msg = decode_udp_message(pkt).unwrap();
        assert_eq!(msg.addr, "8.8.8.8:53");
        out = feed_defrag(&mut map, msg).or(out);
    }
    assert_eq!(out.expect("reassembled payload"), data);
}

#[test]
fn test_tcp_request_frame_shape() {
    let req = encode_tcp_request("example.com:443");
    assert_eq!(&req[..2], &[0x44, 0x01]); // frame type 0x401
    assert_eq!(req[2], 15); // address length
    assert_eq!(&req[3..18], b"example.com:443");
    // Padding length varint (1 byte, or 2 bytes when >= 256) + padding.
    let first = req[18];
    let (pad_len, pad_len_bytes) = if first >> 6 == 0 {
        (first as usize, 1)
    } else {
        ((((first & 0x3f) as usize) << 8) | req[19] as usize, 2)
    };
    assert!((64..512).contains(&pad_len));
    assert_eq!(req.len(), 18 + pad_len_bytes + pad_len);
}

#[test]
fn test_resolve_password_prefers_hy2_auth() {
    let node = Node {
        hy2_auth: Some("hy2-secret".to_string()),
        password: Some("generic-secret".to_string()),
        ..Default::default()
    };
    assert_eq!(Hysteria2Handler::resolve_password(&node), "hy2-secret");
}

#[test]
fn test_resolve_password_falls_back() {
    let node = Node {
        hy2_auth: None,
        password: Some("generic-secret".to_string()),
        ..Default::default()
    };
    assert_eq!(Hysteria2Handler::resolve_password(&node), "generic-secret");
}

#[tokio::test]
async fn test_dial_tcp_echo() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let mut stream = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial should succeed");
    stream.stream.write_all(b"hello hy2").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello hy2");
}

#[tokio::test]
async fn test_dial_tcp_domain_echo() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

    let mut stream = handler
        .dial(&node, target, Some("example.com"), Duration::from_secs(5))
        .await
        .expect("dial should succeed");
    stream.stream.write_all(b"domain").await.unwrap();
    let mut buf = [0u8; 16];
    let n = stream.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"domain");
}

#[tokio::test]
async fn test_wrong_password_rejected() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), "wrong-password");
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let result = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await;
    let err = result.expect_err("bad password must fail the dial");
    assert!(
        format!("{err:#}").contains("authentication failed, status code: 404"),
        "unexpected error: {err:#}"
    );
    assert!(!handler.test_connectivity(&node).await);
}

#[tokio::test]
async fn test_udp_datagram_echo() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

    let udp = handler
        .dial_udp(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial_udp should succeed");
    udp.socket
        .send_to(b"dns-query", udp.relay_addr)
        .await
        .unwrap();
    let mut buf = [0u8; 256];
    let (n, src) = tokio::time::timeout(Duration::from_secs(5), udp.socket.recv_from(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(src, udp.relay_addr);
    assert_eq!(&buf[..n], b"dns-query");
}

#[tokio::test]
async fn test_udp_fragmented_echo() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

    let udp = handler
        .dial_udp(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial_udp should succeed");
    // 3000 bytes exceeds the QUIC datagram MTU: fragmented on send and
    // reassembled on receive.
    let payload = vec![0x5au8; 3000];
    udp.socket.send_to(&payload, udp.relay_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, src) = tokio::time::timeout(Duration::from_secs(5), udp.socket.recv_from(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(src, udp.relay_addr);
    assert_eq!(&buf[..n], payload.as_slice());
}

#[tokio::test]
async fn test_connection_reuse_across_dials() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    for i in 0..3 {
        let mut stream = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await
            .expect("dial should succeed");
        let payload = format!("req{i}");
        stream.stream.write_all(payload.as_bytes()).await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], payload.as_bytes());
    }
}

#[tokio::test]
async fn test_salamander_obfs_tcp_udp_echo() {
    let server_addr = start_obfs_server(TEST_PASSWORD, b"obfs-secret").await;
    let mut node = test_node(server_addr.port(), TEST_PASSWORD);
    node.hy2_obfs = Some("obfs-secret".to_string());
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let mut stream = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial through salamander obfs should succeed");
    stream.stream.write_all(b"obfs hello").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"obfs hello");

    let udp_target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let udp = handler
        .dial_udp(&node, udp_target, None, Duration::from_secs(5))
        .await
        .expect("dial_udp through salamander obfs should succeed");
    udp.socket
        .send_to(b"obfs-dns", udp.relay_addr)
        .await
        .unwrap();
    let mut buf = [0u8; 256];
    let (n, src) = tokio::time::timeout(Duration::from_secs(5), udp.socket.recv_from(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(src, udp.relay_addr);
    assert_eq!(&buf[..n], b"obfs-dns");
}

#[tokio::test]
async fn test_salamander_wrong_obfs_password_rejected() {
    let server_addr = start_obfs_server(TEST_PASSWORD, b"obfs-secret").await;
    let mut node = test_node(server_addr.port(), TEST_PASSWORD);
    node.hy2_obfs = Some("wrong-obfs-password".to_string());
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    // The QUIC handshake cannot complete through mismatched obfuscation;
    // the short connect timeout bounds the failure.
    let result = handler
        .dial(&node, target, None, Duration::from_secs(1))
        .await;
    assert!(result.is_err(), "wrong obfs password must fail the dial");
}

// --- E2E against a real, officially-deployed hysteria2 server ---
//
// Gated on environment variables so CI is unaffected:
//   HONK_HY2_SERVER=host:port   (required; tests skip silently without it)
//   HONK_HY2_PASSWORD=...       (server auth password)
//   HONK_HY2_OBFS=...           (optional salamander obfs password)

fn e2e_node() -> Option<Node> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let server = std::env::var("HONK_HY2_SERVER").ok()?;
    let (host, port) = server.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some(Node {
        name: "hy2-e2e".to_string(),
        protocol: NodeProtocol::Hysteria2,
        host: host.to_string(),
        address: server,
        port,
        hy2_auth: std::env::var("HONK_HY2_PASSWORD").ok(),
        hy2_obfs: std::env::var("HONK_HY2_OBFS")
            .ok()
            .filter(|s| !s.is_empty()),
        hy2_up_mbps: std::env::var("HONK_HY2_UP_MBPS")
            .ok()
            .and_then(|v| v.parse().ok()),
        hy2_down_mbps: std::env::var("HONK_HY2_DOWN_MBPS")
            .ok()
            .and_then(|v| v.parse().ok()),
        hy2_port_hopping: std::env::var("HONK_HY2_MPORT")
            .ok()
            .filter(|s| !s.is_empty()),
        hy2_hop_interval: std::env::var("HONK_HY2_MHOP")
            .ok()
            .and_then(|v| v.parse().ok()),
        tls_pin_sha256: std::env::var("HONK_HY2_PIN")
            .ok()
            .filter(|s| !s.is_empty()),
        hy2_init_stream_recv_window: std::env::var("HONK_HY2_STREAM_RWND")
            .ok()
            .and_then(|v| v.parse().ok()),
        hy2_init_conn_recv_window: std::env::var("HONK_HY2_CONN_RWND")
            .ok()
            .and_then(|v| v.parse().ok()),
        hy2_disable_mtu_discovery: std::env::var("HONK_HY2_DISABLE_PMTUD")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .map(|v| v == 1),
        // Deployed with a self-signed certificate.
        skip_cert_verify: true,
        ..Default::default()
    })
}

#[tokio::test]
async fn test_e2e_real_server_tcp_http() {
    let Some(node) = e2e_node() else {
        eprintln!("HONK_HY2_SERVER unset; skipping real-server e2e");
        return;
    };
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = "104.18.0.204:80".parse().unwrap(); // www.gstatic.com
    let mut stream = handler
        .dial(
            &node,
            target,
            Some("www.gstatic.com"),
            Duration::from_secs(10),
        )
        .await
        .expect("dial through real server should succeed");
    stream
        .stream
        .write_all(
            b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(15),
        stream.stream.read_to_end(&mut response),
    )
    .await
    .expect("response timed out")
    .unwrap();
    let head = String::from_utf8_lossy(&response);
    assert!(
        head.starts_with("HTTP/1.1 204"),
        "expected 204 from generate_204, got: {}",
        &head[..head.len().min(200)]
    );
}

#[tokio::test]
async fn test_e2e_real_server_udp_dns() {
    let Some(node) = e2e_node() else {
        eprintln!("HONK_HY2_SERVER unset; skipping real-server e2e");
        return;
    };
    let handler = Hysteria2Handler::new();
    let target: SocketAddr = std::env::var("HONK_HY2_UDP_TARGET")
        .unwrap_or_else(|_| "8.8.8.8:53".to_string())
        .parse()
        .expect("invalid HONK_HY2_UDP_TARGET");
    let udp = handler
        .dial_udp(&node, target, None, Duration::from_secs(10))
        .await
        .expect("dial_udp through real server should succeed");
    if std::env::var("HONK_HY2_DELAY_MS").is_ok() {
        let ms: u64 = std::env::var("HONK_HY2_DELAY_MS").unwrap().parse().unwrap();
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    // Minimal DNS query: example.com A, RD=1.
    let mut query = vec![
        0x12, 0x34, // id
        0x01, 0x00, // flags: RD
        0x00, 0x01, // qdcount
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar count
    ];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // root, A, IN

    // QUIC datagrams are fire-and-forget: a single packet lost on a
    // throttled path kills the exchange, so retry like a real stub resolver.
    let mut buf = vec![0u8; 2048];
    let mut received = None;
    for attempt in 0..5 {
        udp.socket.send_to(&query, udp.relay_addr).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(4), udp.socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                received = Some(n);
                break;
            }
            _ => eprintln!("DNS attempt {attempt} timed out; retrying"),
        }
    }
    let n = received.expect("DNS reply timed out on all attempts");
    assert!(n >= 12, "DNS reply too short: {n} bytes");
    assert_eq!(&buf[0..2], &[0x12, 0x34], "DNS id mismatch");
    assert_eq!(buf[3] & 0x0f, 0, "DNS rcode must be NOERROR");
    assert!(
        u16::from_be_bytes([buf[6], buf[7]]) >= 1,
        "expected at least one answer"
    );
}

#[test]
fn test_parse_port_hopping() {
    assert_eq!(parse_port_hopping("8080"), Some(vec![8080]));
    assert_eq!(
        parse_port_hopping("20000-20003"),
        Some(vec![20000, 20001, 20002, 20003])
    );
    assert_eq!(
        parse_port_hopping("8080, 9000-9001"),
        Some(vec![8080, 9000, 9001])
    );
    assert_eq!(parse_port_hopping(""), None);
    assert_eq!(parse_port_hopping("abc"), None);
    assert_eq!(parse_port_hopping("9000-8000"), None);
}

#[test]
fn test_hop_state_rotation() {
    // Empty list keeps the base port.
    let mut hop = HopState::new(vec![], Duration::from_millis(10));
    assert_eq!(hop.port(8443), 8443);

    // Single port: hops to it immediately (the base port differs).
    let mut hop = HopState::new(vec![20000], Duration::from_millis(10));
    hop.last_hop = Instant::now() - Duration::from_secs(1);
    assert_eq!(hop.port(8443), 20000);
    // Within the interval the port stays put.
    assert_eq!(hop.port(8443), 20000);

    // Multiple ports: a hop always lands in the list and off the current port.
    let mut hop = HopState::new(vec![20000, 20001, 20002], Duration::from_millis(10));
    let mut seen = std::collections::HashSet::new();
    for _ in 0..10 {
        hop.last_hop = Instant::now() - Duration::from_secs(1);
        let p = hop.port(8443);
        assert!((20000..=20002).contains(&p));
        seen.insert(p);
    }
    assert!(seen.len() > 1, "hops should visit multiple ports: {seen:?}");
}
