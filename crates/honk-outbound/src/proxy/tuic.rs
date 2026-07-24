//! TUIC v5 proxy handler (QUIC), implemented against the sing-quic reference:
//!
//! - Commands: AUTHENTICATE 0x00 / CONNECT 0x01 / PACKET 0x02 / DISSOCIATE
//!   0x03 / HEARTBEAT 0x04, all headed by version 0x05
//!   (`sing-quic/tuic/protocol.go`).
//! - Authentication: one uni stream carrying
//!   `[0x05, 0x00, uuid(16), token(32)]` where
//!   `token = TLS ExportKeyingMaterial(label = uuid bytes, context = password,
//!   len = 32)` (`sing-quic/tuic/client.go:197-214`); the stream is finished
//!   right after the write, like the reference client.
//! - TCP: one bi stream per connection, `[0x05, 0x01, addr]` followed by raw
//!   payload (`client.go:347-364`).
//! - UDP: PACKET frames `[0x05, 0x02, session u16, packet u16, frag_total u8,
//!   frag_id u8, len u16, addr, payload]` sent either as native QUIC datagrams
//!   (default, fragmented when exceeding the datagram MTU) or as one uni
//!   stream per packet when the peer did not negotiate datagram support
//!   (`packet.go:69-87`, `packet.go:302-328`). Responses are demultiplexed by
//!   session id from both paths (`client_packet.go`).
//! - Heartbeat: datagram `[0x05, 0x04]` every 10s while the connection is in
//!   use (`client.go:216-230`).
//! - Address encoding: ATYP 0x00 = domain (len byte + bytes + port),
//!   0x01 = IPv4, 0x02 = IPv6, 0xff = none (continuation fragment)
//!   (`address.go`, sing `metadata` serializer).

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::debug;

use crate::quic::{QuicBiStream, QuicClient};

use super::{ProxyHandler, ProxyStream, UdpProxySocket};

const TUIC_VERSION: u8 = 0x05;

const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;

const ATYP_DOMAIN: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;
const ATYP_NONE: u8 = 0xff;

/// sing-quic default heartbeat interval (`client.go:55-57`).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Close the shared QUIC connection after this long without any open stream.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Grace period after sending AUTHENTICATE for the server to reject bad
/// credentials by closing the connection.
const AUTH_GRACE: Duration = Duration::from_millis(150);
/// Tear down a UDP session bridge after this long without traffic.
const UDP_BRIDGE_IDLE: Duration = Duration::from_secs(90);
/// Maximum pending fragmented packets kept for reassembly per session.
const DEFRAG_MAX_PENDING: usize = 64;
/// Maximum age of a pending fragmented packet before it is dropped.
const DEFRAG_MAX_AGE: Duration = Duration::from_secs(10);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// TUIC address (sing socksaddr wire format).
#[derive(Debug, Clone, PartialEq, Eq)]
enum TuicAddr {
    None,
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String, u16),
}

impl TuicAddr {
    fn new(target: SocketAddr, target_domain: Option<&str>) -> Self {
        if let Some(domain) = target_domain {
            return TuicAddr::Domain(domain.to_string(), target.port());
        }
        match target {
            SocketAddr::V4(v4) => TuicAddr::V4(v4),
            SocketAddr::V6(v6) => TuicAddr::V6(v6),
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            TuicAddr::None => 1,
            TuicAddr::V4(_) => 1 + 4 + 2,
            TuicAddr::V6(_) => 1 + 16 + 2,
            TuicAddr::Domain(d, _) => 1 + 1 + d.len() + 2,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            TuicAddr::None => out.push(ATYP_NONE),
            TuicAddr::V4(v4) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            TuicAddr::V6(v6) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
            TuicAddr::Domain(domain, port) => {
                out.push(ATYP_DOMAIN);
                out.push(domain.len().min(u8::MAX as usize) as u8);
                out.extend_from_slice(domain.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// Decode from a byte slice, advancing the cursor past the address.
    fn decode(cursor: &mut &[u8]) -> io::Result<TuicAddr> {
        fn take<'a>(cursor: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
            if cursor.len() < n {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short address",
                ));
            }
            let (head, tail) = cursor.split_at(n);
            *cursor = tail;
            Ok(head)
        }
        let atyp = take(cursor, 1)?[0];
        match atyp {
            ATYP_IPV4 => {
                let ip: [u8; 4] = take(cursor, 4)?.try_into().expect("slice length checked");
                let port = u16::from_be_bytes(take(cursor, 2)?.try_into().expect("len checked"));
                Ok(TuicAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            ATYP_IPV6 => {
                let ip: [u8; 16] = take(cursor, 16)?.try_into().expect("slice length checked");
                let port = u16::from_be_bytes(take(cursor, 2)?.try_into().expect("len checked"));
                Ok(TuicAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )))
            }
            ATYP_DOMAIN => {
                let len = take(cursor, 1)?[0] as usize;
                let domain = take(cursor, len)?;
                let domain = std::str::from_utf8(domain)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                    .to_string();
                let port = u16::from_be_bytes(take(cursor, 2)?.try_into().expect("len checked"));
                Ok(TuicAddr::Domain(domain, port))
            }
            ATYP_NONE => Ok(TuicAddr::None),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown address type {other:#x}"),
            )),
        }
    }

    /// Read an address from a QUIC stream (used for inbound UDP-over-stream
    /// packets).
    async fn read_from_stream(recv: &mut quinn::RecvStream) -> io::Result<TuicAddr> {
        let mut atyp = [0u8; 1];
        read_exact(recv, &mut atyp).await?;
        match atyp[0] {
            ATYP_IPV4 => {
                let mut buf = [0u8; 4 + 2];
                read_exact(recv, &mut buf).await?;
                let ip: [u8; 4] = buf[..4].try_into().expect("array length");
                let port = u16::from_be_bytes(buf[4..].try_into().expect("array length"));
                Ok(TuicAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 16 + 2];
                read_exact(recv, &mut buf).await?;
                let ip: [u8; 16] = buf[..16].try_into().expect("array length");
                let port = u16::from_be_bytes(buf[16..].try_into().expect("array length"));
                Ok(TuicAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )))
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                read_exact(recv, &mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                read_exact(recv, &mut domain).await?;
                let mut port = [0u8; 2];
                read_exact(recv, &mut port).await?;
                let domain = String::from_utf8(domain)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(TuicAddr::Domain(domain, u16::from_be_bytes(port)))
            }
            ATYP_NONE => Ok(TuicAddr::None),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown address type {other:#x}"),
            )),
        }
    }
}

async fn read_exact(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> io::Result<()> {
    recv.read_exact(buf)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))
}

/// An inbound UDP packet delivered to a session bridge.
#[derive(Debug)]
struct UdpInbound {
    session_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    #[allow(dead_code)] // address is informational; the relay keys sessions by target
    addr: TuicAddr,
    data: Vec<u8>,
}

/// Decode a PACKET frame body (everything after `[version, command]`).
fn decode_udp_message(data: &[u8]) -> io::Result<UdpInbound> {
    if data.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short UDP message",
        ));
    }
    let session_id = u16::from_be_bytes(data[0..2].try_into().expect("len checked"));
    let packet_id = u16::from_be_bytes(data[2..4].try_into().expect("len checked"));
    let frag_total = data[4];
    let frag_id = data[5];
    let size = u16::from_be_bytes(data[6..8].try_into().expect("len checked")) as usize;
    let mut cursor = &data[8..];
    let addr = TuicAddr::decode(&mut cursor)?;
    if cursor.len() != size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "UDP message length mismatch",
        ));
    }
    Ok(UdpInbound {
        session_id,
        packet_id,
        frag_total,
        frag_id,
        addr,
        data: cursor.to_vec(),
    })
}

/// Read a full PACKET frame (after `[version, command]`) from a uni stream.
async fn read_udp_message_stream(recv: &mut quinn::RecvStream) -> io::Result<UdpInbound> {
    let mut fixed = [0u8; 8];
    read_exact(recv, &mut fixed).await?;
    let session_id = u16::from_be_bytes(fixed[0..2].try_into().expect("array length"));
    let packet_id = u16::from_be_bytes(fixed[2..4].try_into().expect("array length"));
    let frag_total = fixed[4];
    let frag_id = fixed[5];
    let size = u16::from_be_bytes(fixed[6..8].try_into().expect("array length")) as usize;
    let addr = TuicAddr::read_from_stream(recv).await?;
    let mut data = vec![0u8; size];
    read_exact(recv, &mut data).await?;
    Ok(UdpInbound {
        session_id,
        packet_id,
        frag_total,
        frag_id,
        addr,
        data,
    })
}

/// Encode one PACKET frame (including the `[version, command]` head).
fn encode_udp_packet(
    session_id: u16,
    packet_id: u16,
    frag_total: u8,
    frag_id: u8,
    addr: &TuicAddr,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + addr.encoded_len() + data.len());
    out.push(TUIC_VERSION);
    out.push(CMD_PACKET);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    addr.encode(&mut out);
    out.extend_from_slice(data);
    out
}

/// Build the datagram sequence for one UDP payload, fragmenting like sing's
/// `fragUDPMessage` when it exceeds the datagram MTU: the first fragment
/// carries the address, continuation fragments use ATYP 0xff.
fn fragment_udp_packets(
    session_id: u16,
    packet_id: u16,
    addr: &TuicAddr,
    data: &[u8],
    max_datagram: usize,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let first_header = 10 + addr.encoded_len();
    if first_header + data.len() <= max_datagram {
        return Ok(vec![encode_udp_packet(
            session_id, packet_id, 1, 0, addr, data,
        )]);
    }
    let cont_header = 10 + TuicAddr::None.encoded_len();
    let first_cap = max_datagram.saturating_sub(first_header);
    let cont_cap = max_datagram.saturating_sub(cont_header);
    if first_cap == 0 || cont_cap == 0 {
        anyhow::bail!("datagram MTU {max_datagram} too small for the packet header");
    }
    let frag_total = 1 + (data.len() - first_cap).div_ceil(cont_cap);
    if frag_total > u8::MAX as usize {
        anyhow::bail!("UDP payload {} bytes needs too many fragments", data.len());
    }
    let mut out = Vec::with_capacity(frag_total);
    let mut offset = 0;
    for frag_id in 0..frag_total {
        let cap = if frag_id == 0 { first_cap } else { cont_cap };
        let end = (offset + cap).min(data.len());
        let frag_addr = if frag_id == 0 {
            addr.clone()
        } else {
            TuicAddr::None
        };
        out.push(encode_udp_packet(
            session_id,
            packet_id,
            frag_total as u8,
            frag_id as u8,
            &frag_addr,
            &data[offset..end],
        ));
        offset = end;
    }
    Ok(out)
}

/// Reassembly state for one fragmented packet (sing `udpDefragger` parity).
struct DefragBuffer {
    frags: Vec<Option<UdpInbound>>,
    count: usize,
    updated: Instant,
}

/// Feed one inbound packet into the defragmenter; returns the reassembled
/// payload when the last missing fragment arrives.
fn feed_defrag(map: &mut HashMap<u16, DefragBuffer>, msg: UdpInbound) -> Option<Vec<u8>> {
    if msg.frag_total <= 1 {
        return Some(msg.data);
    }
    if msg.frag_id >= msg.frag_total {
        return None;
    }
    if map.len() >= DEFRAG_MAX_PENDING && !map.contains_key(&msg.packet_id) {
        map.retain(|_, b| b.updated.elapsed() < DEFRAG_MAX_AGE);
        if map.len() >= DEFRAG_MAX_PENDING {
            return None;
        }
    }
    let packet_id = msg.packet_id;
    let frag_total = msg.frag_total as usize;
    let entry = map.entry(packet_id).or_insert_with(|| DefragBuffer {
        frags: (0..frag_total).map(|_| None).collect(),
        count: 0,
        updated: Instant::now(),
    });
    if entry.frags.len() != frag_total {
        entry.frags = (0..frag_total).map(|_| None).collect();
        entry.count = 0;
    }
    let frag_id = msg.frag_id as usize;
    if entry.frags[frag_id].is_some() {
        return None;
    }
    entry.frags[frag_id] = Some(msg);
    entry.count += 1;
    entry.updated = Instant::now();
    if entry.count != entry.frags.len() {
        return None;
    }
    let entry = map.remove(&packet_id).expect("entry just inserted");
    let mut data = Vec::new();
    for frag in entry.frags.into_iter().flatten() {
        data.extend_from_slice(&frag.data);
    }
    Some(data)
}

type SessionMap = Arc<Mutex<HashMap<u16, mpsc::UnboundedSender<UdpInbound>>>>;

/// Per-QUIC-connection protocol state (demux maps, counters, task set).
struct TuicConnState {
    conn: quinn::Connection,
    /// UDP-over-stream fallback: the peer did not negotiate QUIC datagrams.
    udp_over_stream: bool,
    sessions: SessionMap,
    next_session: AtomicU16,
    /// Number of open TCP streams + UDP bridges on this connection.
    open: Arc<AtomicUsize>,
    /// Last activity (unix seconds) for the idle-connection reaper.
    last_activity: Arc<AtomicU64>,
}

impl TuicConnState {
    fn new(conn: quinn::Connection) -> Self {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let state = Self {
            udp_over_stream: conn.max_datagram_size().is_none(),
            conn: conn.clone(),
            sessions: Arc::clone(&sessions),
            next_session: AtomicU16::new(0),
            open: Arc::new(AtomicUsize::new(0)),
            last_activity: Arc::new(AtomicU64::new(now_secs())),
        };
        tokio::spawn(Self::datagram_loop(conn.clone(), Arc::clone(&sessions)));
        tokio::spawn(Self::uni_stream_loop(conn.clone(), Arc::clone(&sessions)));
        if !state.udp_over_stream {
            tokio::spawn(Self::heartbeat_loop(
                conn,
                Arc::downgrade(&state.open),
                Arc::downgrade(&state.last_activity),
            ));
        } else {
            tokio::spawn(Self::idle_reaper_loop(
                conn,
                Arc::downgrade(&state.open),
                Arc::downgrade(&state.last_activity),
            ));
        }
        state
    }

    fn touch(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
    }

    fn alloc_session(&self) -> u16 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    /// Inbound QUIC datagrams: PACKET frames are demultiplexed by session id
    /// (sing `loopMessages`, `client_packet.go:12-50`).
    async fn datagram_loop(conn: quinn::Connection, sessions: SessionMap) {
        loop {
            let data = match conn.read_datagram().await {
                Ok(data) => data,
                Err(_) => break,
            };
            if data.len() < 2 || data[0] != TUIC_VERSION {
                continue;
            }
            match data[1] {
                CMD_PACKET => {
                    if let Ok(msg) = decode_udp_message(&data[2..]) {
                        let tx = sessions.lock().get(&msg.session_id).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send(msg);
                        }
                    }
                }
                CMD_HEARTBEAT => {}
                other => debug!("TUIC: ignoring unknown datagram command {other:#x}"),
            }
        }
        // Connection died: drop all session senders so bridges terminate.
        sessions.lock().clear();
    }

    /// Inbound uni streams carry one PACKET frame each in UDP-over-stream
    /// mode (sing `loopUniStreams`, `client_packet.go:52-93`).
    async fn uni_stream_loop(conn: quinn::Connection, sessions: SessionMap) {
        loop {
            let mut recv = match conn.accept_uni().await {
                Ok(recv) => recv,
                Err(_) => break,
            };
            let sessions = Arc::clone(&sessions);
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if read_exact(&mut recv, &mut head).await.is_err() {
                    return;
                }
                if head[0] != TUIC_VERSION || head[1] != CMD_PACKET {
                    return;
                }
                if let Ok(msg) = read_udp_message_stream(&mut recv).await {
                    let tx = sessions.lock().get(&msg.session_id).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(msg);
                    }
                }
            });
        }
    }

    /// Heartbeat datagrams every 10s while the connection is in use; closes
    /// the connection after it has been idle (no open streams/bridges) for
    /// [`CONN_IDLE_TIMEOUT`] so abandoned cache entries do not keep
    /// heartbeating forever.
    async fn heartbeat_loop(
        conn: quinn::Connection,
        open: std::sync::Weak<AtomicUsize>,
        last_activity: std::sync::Weak<AtomicU64>,
    ) {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            if conn.close_reason().is_some() {
                break;
            }
            if Self::idle_timed_out(&conn, &open, &last_activity) {
                break;
            }
            if conn
                .send_datagram(bytes::Bytes::from_static(&[TUIC_VERSION, CMD_HEARTBEAT]))
                .is_err()
            {
                break;
            }
        }
    }

    /// Same idle reaping as [`heartbeat_loop`] for connections without
    /// datagram support (no heartbeat frames can be sent there).
    async fn idle_reaper_loop(
        conn: quinn::Connection,
        open: std::sync::Weak<AtomicUsize>,
        last_activity: std::sync::Weak<AtomicU64>,
    ) {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            if conn.close_reason().is_some() {
                break;
            }
            if Self::idle_timed_out(&conn, &open, &last_activity) {
                break;
            }
        }
    }

    /// Returns true (after closing the connection) when the owning state was
    /// dropped or the connection has been idle for too long.
    fn idle_timed_out(
        conn: &quinn::Connection,
        open: &std::sync::Weak<AtomicUsize>,
        last_activity: &std::sync::Weak<AtomicU64>,
    ) -> bool {
        let (Some(open), Some(last)) = (open.upgrade(), last_activity.upgrade()) else {
            // Protocol state dropped: nothing can use this connection anymore.
            conn.close(quinn::VarInt::from_u32(0), b"state dropped");
            return true;
        };
        let idle = now_secs().saturating_sub(last.load(Ordering::Relaxed));
        if open.load(Ordering::Relaxed) == 0 && idle > CONN_IDLE_TIMEOUT.as_secs() {
            conn.close(quinn::VarInt::from_u32(0), b"idle");
            return true;
        }
        false
    }
}

struct TuicClient {
    quic: QuicClient<TuicConnState>,
    uuid: [u8; 16],
    password: String,
}

impl TuicClient {
    async fn connection(
        &self,
        connect_timeout: Duration,
    ) -> anyhow::Result<(quinn::Connection, Arc<TuicConnState>)> {
        let uuid = self.uuid;
        let password = self.password.clone();
        self.quic
            .connection_with(connect_timeout, move |conn| async move {
                authenticate(&conn, &uuid, &password).await?;
                Ok(TuicConnState::new(conn))
            })
            .await
    }
}

/// TUIC authenticate: uni stream `[0x05, 0x00, uuid, token]` where the token
/// is the TLS keying-material exporter keyed by uuid and password
/// (sing `clientHandshake`, `client.go:197-214`).
async fn authenticate(
    conn: &quinn::Connection,
    uuid: &[u8; 16],
    password: &str,
) -> anyhow::Result<()> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| anyhow!("TUIC: TLS keying material export failed: {e:?}"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.push(TUIC_VERSION);
    auth.push(CMD_AUTHENTICATE);
    auth.extend_from_slice(uuid);
    auth.extend_from_slice(&token);
    let mut stream = conn
        .open_uni()
        .await
        .context("TUIC: open authenticate stream")?;
    stream
        .write_all(&auth)
        .await
        .context("TUIC: send authenticate")?;
    stream
        .finish()
        .context("TUIC: finish authenticate stream")?;
    // There is no positive auth acknowledgement in the protocol; a server
    // that rejects the credentials closes the connection. Give it a brief
    // grace period so a bad password surfaces as a dial error here instead
    // of a stream failure on the first proxied connection.
    tokio::select! {
        e = conn.closed() => Err(anyhow!("TUIC: connection closed during authentication: {e}")),
        _ = tokio::time::sleep(AUTH_GRACE) => Ok(()),
    }
}

/// TUIC proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct TuicHandler;

/// Shared TUIC clients keyed by server + credentials (anytls pool parity).
static CLIENTS: LazyLock<Mutex<HashMap<String, Arc<TuicClient>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

impl TuicHandler {
    pub fn new() -> Self {
        Self
    }

    async fn client_for(node: &Node) -> anyhow::Result<Arc<TuicClient>> {
        let uuid_str = node
            .tuic_uuid
            .as_deref()
            .or(node.username.as_deref())
            .ok_or_else(|| anyhow!("TUIC node '{}': missing tuic_uuid", node.name))?;
        let uuid = uuid::Uuid::parse_str(uuid_str)
            .with_context(|| format!("TUIC node '{}': invalid uuid", node.name))?;
        let password = node
            .tuic_password
            .as_deref()
            .or(node.password.as_deref())
            .unwrap_or("")
            .to_string();
        let key = format!(
            "{}|{}|{}|{}|{}|{}",
            node.host(),
            node.port,
            uuid_str,
            password,
            node.sni.as_deref().unwrap_or(""),
            node.skip_cert_verify
        );
        if let Some(client) = CLIENTS.lock().get(&key) {
            return Ok(Arc::clone(client));
        }
        // Build outside the lock: client_config is async (ECH discovery).
        let server_name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
        let config = crate::quic::client_config(
            node,
            &[b"tuic"],
            crate::quic::QuicClientOptions::with_congestion(node.tuic_congestion.as_deref()),
        )
        .await?;
        let client = Arc::new(TuicClient {
            quic: QuicClient::new(node.host().to_string(), node.port, server_name, config),
            uuid: *uuid.as_bytes(),
            password,
        });
        // Another task may have won the race — reuse theirs.
        let mut clients = CLIENTS.lock();
        Ok(clients
            .entry(key)
            .or_insert_with(|| Arc::clone(&client))
            .clone())
    }

    async fn send_udp(
        state: &TuicConnState,
        session_id: u16,
        packet_id: u16,
        addr: &TuicAddr,
        data: &[u8],
    ) -> anyhow::Result<()> {
        if data.len() > u16::MAX as usize {
            anyhow::bail!("UDP payload too large: {} bytes", data.len());
        }
        state.touch();
        if state.udp_over_stream {
            // One uni stream per packet (sing `writePacket` udpStream branch).
            let pkt = encode_udp_packet(session_id, packet_id, 1, 0, addr, data);
            let mut stream = state.conn.open_uni().await?;
            stream.write_all(&pkt).await?;
            stream.finish()?;
            return Ok(());
        }
        let max_datagram = state.conn.max_datagram_size().unwrap_or(1200);
        for pkt in fragment_udp_packets(session_id, packet_id, addr, data, max_datagram)? {
            state.conn.send_datagram(bytes::Bytes::from(pkt))?;
        }
        Ok(())
    }

    async fn send_dissociate(conn: &quinn::Connection, session_id: u16) {
        if let Ok(mut stream) = conn.open_uni().await {
            let mut buf = Vec::with_capacity(4);
            buf.push(TUIC_VERSION);
            buf.push(CMD_DISSOCIATE);
            buf.extend_from_slice(&session_id.to_be_bytes());
            let _ = stream.write_all(&buf).await;
            let _ = stream.finish();
        }
    }
}

#[async_trait]
impl ProxyHandler for TuicHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::Tuic
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let client = Self::client_for(node).await?;
        let addr = TuicAddr::new(target, target_domain);
        let mut last_err: Option<anyhow::Error> = None;
        // Retry once with a fresh connection when the stream open fails on a
        // half-dead cached connection.
        for attempt in 0..2 {
            let (conn, state) = client.connection(connect_timeout).await?;
            state.touch();
            let result = async {
                let (mut send, recv) = conn.open_bi().await.context("TUIC: open stream")?;
                let mut header = Vec::with_capacity(2 + addr.encoded_len());
                header.push(TUIC_VERSION);
                header.push(CMD_CONNECT);
                addr.encode(&mut header);
                send.write_all(&header)
                    .await
                    .context("TUIC: send CONNECT")?;
                Ok::<_, anyhow::Error>((send, recv))
            }
            .await;
            match result {
                Ok((send, recv)) => {
                    state.open.fetch_add(1, Ordering::Relaxed);
                    let open = Arc::clone(&state.open);
                    let stream = QuicBiStream::new(send, recv).with_on_drop(move || {
                        open.fetch_sub(1, Ordering::Relaxed);
                    });
                    return Ok(ProxyStream {
                        stream: Box::new(stream),
                        target_addr: target,
                        target_domain: target_domain.map(str::to_string),
                    });
                }
                Err(e) => {
                    debug!("TUIC: stream open failed (attempt {attempt}): {e}");
                    client.quic.invalidate(&conn).await;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("loop runs at least once"))
    }

    async fn dial_udp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<UdpProxySocket> {
        let client = Self::client_for(node).await?;
        let (conn, state) = client.connection(connect_timeout).await?;
        state.touch();
        let session_id = state.alloc_session();
        let target_addr = TuicAddr::new(target, target_domain);

        // Bridge the QUIC tunnel to a local UDP socket pair: the relay sends
        // raw payloads to `relay_addr` on the returned socket and receives
        // replies from the same address (see UdpProxySocket users).
        let external = crate::util::udp_loopback_bind().await?;
        let internal = crate::util::udp_loopback_bind().await?;
        let external_addr = external.local_addr()?;
        let relay_addr = internal.local_addr()?;

        let (tx, mut rx) = mpsc::unbounded_channel::<UdpInbound>();
        state.sessions.lock().insert(session_id, tx);

        let bridge_state = Arc::clone(&state);
        bridge_state.open.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let mut defrag: HashMap<u16, DefragBuffer> = HashMap::new();
            let mut packet_id: u16 = 0;
            let mut buf = vec![0u8; 65536];
            loop {
                tokio::select! {
                    result = internal.recv_from(&mut buf) => {
                        match result {
                            Ok((n, src)) => {
                                if src != external_addr {
                                    continue;
                                }
                                packet_id = packet_id.wrapping_add(1);
                                if let Err(e) = Self::send_udp(
                                    &bridge_state,
                                    session_id,
                                    packet_id,
                                    &target_addr,
                                    &buf[..n],
                                )
                                .await
                                {
                                    debug!("TUIC UDP: send failed: {e}");
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    msg = rx.recv() => {
                        match msg {
                            Some(msg) => {
                                if let Some(data) = feed_defrag(&mut defrag, msg)
                                    && internal.send_to(&data, external_addr).await.is_err()
                                {
                                    break;
                                }
                            }
                            // Demux gone (connection died).
                            None => break,
                        }
                    }
                    _ = tokio::time::sleep(UDP_BRIDGE_IDLE) => break,
                }
            }
            bridge_state.sessions.lock().remove(&session_id);
            bridge_state.open.fetch_sub(1, Ordering::Relaxed);
            Self::send_dissociate(&conn, session_id).await;
        });

        Ok(UdpProxySocket {
            socket: Arc::new(external),
            relay_addr,
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
            _control: None,
        })
    }

    async fn dial_with_tcp(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _tcp: tokio::net::TcpStream,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!("TUIC runs over QUIC; a bare TCP connection cannot be reused")
    }

    async fn test_connectivity(&self, node: &Node) -> bool {
        match Self::client_for(node).await {
            Ok(client) => client.connection(Duration::from_secs(5)).await.is_ok(),
            Err(e) => {
                debug!("TUIC connectivity test failed for {}: {}", node.name, e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::testutil;
    use quinn::VarInt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const TEST_PASSWORD: &str = "tuic-test-password";

    fn test_node(port: u16, password: &str) -> Node {
        Node {
            name: "tuic-test".to_string(),
            protocol: NodeProtocol::Tuic,
            host: "127.0.0.1".to_string(),
            address: format!("127.0.0.1:{port}"),
            port,
            tuic_uuid: Some(TEST_UUID.to_string()),
            tuic_password: Some(password.to_string()),
            skip_cert_verify: true,
            ..Default::default()
        }
    }

    /// Minimal in-process TUIC v5 server: verifies the AUTHENTICATE token
    /// with the same TLS exporter, echoes CONNECT streams back, echoes UDP
    /// packets back on the path they arrived (datagram or uni stream).
    async fn start_server(datagrams: bool, password: &'static str) -> SocketAddr {
        let (endpoint, addr) = testutil::server_endpoint(&[b"tuic"], datagrams).unwrap();
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
        // Uni streams: authenticate + UDP-over-stream packets.
        let uni_conn = conn.clone();
        tokio::spawn(async move {
            loop {
                let Ok(mut recv) = uni_conn.accept_uni().await else {
                    break;
                };
                let conn = uni_conn.clone();
                tokio::spawn(async move {
                    let mut head = [0u8; 2];
                    if read_exact(&mut recv, &mut head).await.is_err() {
                        return;
                    }
                    match (head[0], head[1]) {
                        (TUIC_VERSION, CMD_AUTHENTICATE) => {
                            let mut rest = [0u8; 48];
                            if read_exact(&mut recv, &mut rest).await.is_err() {
                                return;
                            }
                            let uuid: &[u8; 16] = rest[..16].try_into().unwrap();
                            let mut token = [0u8; 32];
                            if conn
                                .export_keying_material(&mut token, uuid, password.as_bytes())
                                .is_err()
                            {
                                return;
                            }
                            if token != rest[16..] {
                                conn.close(VarInt::from_u32(0xfffffff1), b"authentication failed");
                            }
                        }
                        (TUIC_VERSION, CMD_PACKET) => {
                            let Ok(msg) = read_udp_message_stream(&mut recv).await else {
                                return;
                            };
                            // Echo the packet back on a fresh uni stream.
                            let pkt = encode_udp_packet(
                                msg.session_id,
                                msg.packet_id,
                                msg.frag_total,
                                msg.frag_id,
                                &msg.addr,
                                &msg.data,
                            );
                            if let Ok(mut send) = conn.open_uni().await {
                                let _ = send.write_all(&pkt).await;
                                let _ = send.finish();
                            }
                        }
                        _ => {}
                    }
                });
            }
        });
        // Bi streams: CONNECT echo.
        let bi_conn = conn.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut send, mut recv)) = bi_conn.accept_bi().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut head = [0u8; 2];
                    if read_exact(&mut recv, &mut head).await.is_err() {
                        return;
                    }
                    if head != [TUIC_VERSION, CMD_CONNECT] {
                        return;
                    }
                    if TuicAddr::read_from_stream(&mut recv).await.is_err() {
                        return;
                    }
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
                });
            }
        });
        // Datagrams: echo PACKET frames verbatim.
        loop {
            let Ok(data) = conn.read_datagram().await else {
                break;
            };
            if data.len() >= 2 && data[0] == TUIC_VERSION && data[1] == CMD_PACKET {
                let _ = conn.send_datagram(data);
            }
        }
    }

    #[tokio::test]
    async fn test_dial_tcp_echo() {
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let mut stream = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await
            .expect("dial should succeed");
        stream.stream.write_all(b"hello tuic").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello tuic");
    }

    #[tokio::test]
    async fn test_dial_tcp_domain_echo() {
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
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
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), "wrong-password");
        let handler = TuicHandler::new();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let result = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await;
        assert!(result.is_err(), "bad password must fail the dial");
        assert!(!handler.test_connectivity(&node).await);
    }

    #[tokio::test]
    async fn test_udp_native_datagram_echo() {
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
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
    async fn test_udp_over_stream_echo() {
        // Server without QUIC datagram support → UDP-over-stream fallback.
        let server_addr = start_server(false, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let udp = handler
            .dial_udp(&node, target, None, Duration::from_secs(5))
            .await
            .expect("dial_udp should succeed");
        udp.socket
            .send_to(b"stream-query", udp.relay_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, src) = tokio::time::timeout(Duration::from_secs(5), udp.socket.recv_from(&mut buf))
            .await
            .expect("reply timed out")
            .unwrap();
        assert_eq!(src, udp.relay_addr);
        assert_eq!(&buf[..n], b"stream-query");
    }

    #[tokio::test]
    async fn test_connection_reuse_across_dials() {
        let server_addr = start_server(true, TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = TuicHandler::new();
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

    #[test]
    fn test_addr_codec_roundtrip() {
        let cases = [
            TuicAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 80)),
            TuicAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                443,
                0,
                0,
            )),
            TuicAddr::Domain("example.com".to_string(), 8080),
            TuicAddr::None,
        ];
        for addr in cases {
            let mut buf = Vec::new();
            addr.encode(&mut buf);
            assert_eq!(buf.len(), addr.encoded_len());
            let mut cursor = &buf[..];
            let decoded = TuicAddr::decode(&mut cursor).unwrap();
            assert_eq!(decoded, addr);
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn test_udp_message_codec_roundtrip() {
        let addr = TuicAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
        let pkt = encode_udp_packet(7, 42, 1, 0, &addr, b"payload");
        assert_eq!(pkt[0], TUIC_VERSION);
        assert_eq!(pkt[1], CMD_PACKET);
        let msg = decode_udp_message(&pkt[2..]).unwrap();
        assert_eq!(msg.session_id, 7);
        assert_eq!(msg.packet_id, 42);
        assert_eq!(msg.frag_total, 1);
        assert_eq!(msg.frag_id, 0);
        assert_eq!(msg.addr, addr);
        assert_eq!(msg.data, b"payload");
    }

    #[test]
    fn test_fragmentation_and_defrag() {
        let addr = TuicAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
        let data = vec![0xabu8; 3000];
        let max = 1200;
        let frags = fragment_udp_packets(1, 99, &addr, &data, max).unwrap();
        assert_eq!(frags.len(), 3);
        assert!(frags.iter().all(|f| f.len() <= max));

        let mut map: HashMap<u16, DefragBuffer> = HashMap::new();
        let mut out = None;
        // Feed out of order; only the last missing fragment completes it.
        for pkt in frags.iter().rev() {
            let msg = decode_udp_message(&pkt[2..]).unwrap();
            out = feed_defrag(&mut map, msg).or(out);
        }
        assert_eq!(out.expect("reassembled payload"), data);
    }

    #[test]
    fn test_fragmentation_small_packet_not_fragmented() {
        let addr = TuicAddr::Domain("example.com".to_string(), 443);
        let data = b"tiny";
        let frags = fragment_udp_packets(1, 1, &addr, data, 1200).unwrap();
        assert_eq!(frags.len(), 1);
        let msg = decode_udp_message(&frags[0][2..]).unwrap();
        assert_eq!(msg.frag_total, 1);
        assert_eq!(msg.addr, addr);
        assert_eq!(msg.data, data);
    }
}
