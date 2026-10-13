use super::*;

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
        let transport = Arc::new(
            ShadowsocksHandler::udp_transport(&node, target, domain, STEP_2022)
                .await
                .unwrap(),
        );
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
            [addr_v4_v6(a), b"o".to_vec()].concat(),
            "a name other than the dialed one goes out numerically"
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
        assert_eq!(
            crate::proxy::io_packet_rejection(&error),
            Some(crate::proxy::PacketRejection::InvalidSize),
            "a socket size refusal is local, not a dead tunnel"
        );
        shared.send(a, b"alive").await;
        let (_, alive) = shared.server_recv().await;
        assert_eq!(alive.rest[7..], b"alive"[..]);
        assert_eq!(alive.packet_id, 2, "a refused send still spends a counter");
    }
}
