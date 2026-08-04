//! Hysteria2 proxy handler over real QUIC (quinn), wire-compatible with the
//! official hysteria2 server and sing-box's hysteria2 outbound.
//!
//! Protocol summary, implemented against the sing-quic reference
//! (`sing-box/vendor/github.com/sagernet/sing-quic/hysteria2/`):
//!
//! - **Transport**: QUIC with ALPN `h3` (`client.go:100-102` — hysteria2
//!   speaks HTTP/3 for authentication; the hysteria1 ALPN `hysteria` does not
//!   apply here). Keep-alive every 10s (`hysteria/protocol.go:21`).
//! - **Authentication** (`internal/protocol/http.go`, `client.go:533-605`):
//!   an HTTP/3 `POST https://hysteria/auth` request on a client bi stream
//!   carrying the `Hysteria-Auth` (password), `Hysteria-CC-RX` (receive
//!   bandwidth, 0 = unset) and `Hysteria-Padding` headers. The server answers
//!   with status **233** on success plus `Hysteria-UDP` / `Hysteria-CC-RX`
//!   response headers; anything else means authentication failed.
//! - **TCP** (`internal/protocol/proxy.go:32-151`, `service.go:330-360`): one
//!   bi stream per connection starting with frame type `0x401`, then the
//!   target address (`varint len + "host:port"`) and random padding. The
//!   server replies with a status byte, a message string, and padding; the
//!   stream then becomes the raw data channel.
//! - **UDP** (`internal/protocol/proxy.go:153-221`, `packet.go`): QUIC
//!   datagrams (RFC 9221) carrying
//!   `[session u32 BE][packet u16 BE][frag u8][frag_total u8][vstring addr][data]`,
//!   fragmented at the datagram MTU (every fragment repeats the full header),
//!   max payload 4096 bytes. Sessions are client-allocated `u32` ids.
//! - **Salamander obfuscation** (`salamander.go`): when `hy2_obfs` is set,
//!   every UDP datagram on the wire gets an 8-byte random salt prefix and the
//!   payload XORed with `BLAKE2b-256(password ++ salt)` repeated. Implemented
//!   as a custom quinn `AsyncUdpSocket` (`SalamanderSocket`).
//! - **Congestion control**: without bandwidth hints the connection runs BBR
//!   and sends `Hysteria-CC-RX: 0` (sing-quic's non-brutal default,
//!   `client.go:580-588`). When `hy2_up_mbps` is set the send side uses a
//!   fixed-rate brutal sender ([`crate::quic::BrutalConfig`]); when
//!   `hy2_down_mbps` is set it is advertised via `Hysteria-CC-RX` so the
//!   server's brutal sender paces the downlink.
//!
//! ## HTTP/3 layer
//!
//! The workspace has no HTTP/3 crate, so this module implements the minimal
//! subset needed for the auth exchange: a client preface (control stream with
//! SETTINGS, empty QPACK encoder/decoder streams), HEADERS frames, and a
//! QPACK field-section codec (static table only, with HPACK Huffman decoding
//! since quic-go's server encoder Huffman-codes all literal strings). Request
//! headers are emitted without Huffman (valid QPACK; quic-go's decoder
//! accepts both forms).

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use honk_config::node::Node;
use quinn::{AsyncUdpSocket, Endpoint, UdpPoller};
use rand::RngExt;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use tracing::debug;

use crate::quic::defrag::Defragmenter;
use crate::quic::{QuicClient, QuicConnState, now_secs, recv_read_exact as read_exact};

use super::{
    PacketOutbound, PacketTransport, ProbeableOutbound, ProxyStream, TcpOutbound, WarmableOutbound,
};

/// Auth request target: `POST https://hysteria/auth` (`protocol/http.go:8-10`).
const URL_HOST: &str = "hysteria";
const URL_PATH: &str = "/auth";

const HEADER_AUTH: &str = "hysteria-auth";
const HEADER_UDP: &str = "hysteria-udp";
const HEADER_CC_RX: &str = "hysteria-cc-rx";
const HEADER_PADDING: &str = "hysteria-padding";

/// Authentication success status (`protocol/http.go:17`).
const STATUS_AUTH_OK: u16 = 233;

/// TCP request frame type on a client bi stream (`protocol/proxy.go:16`).
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// DoS guards mirrored from `protocol/proxy.go:19-24`.
const MAX_ADDRESS_LENGTH: u64 = 2048;
const MAX_MESSAGE_LENGTH: u64 = 2048;
const MAX_PADDING_LENGTH: u64 = 4096;
const MAX_UDP_SIZE: usize = 4096;

/// Padding ranges (`protocol/padding.go:26-31`).
const AUTH_PADDING_MIN: usize = 256;
const AUTH_PADDING_MAX: usize = 2048;
const TCP_PADDING_MIN: usize = 64;
const TCP_PADDING_MAX: usize = 512;

/// QUIC keep-alive (`hysteria/protocol.go:21`).
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Close the shared QUIC connection after this long without open streams.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Generous cap for one HEADERS frame payload (the auth response is ~3 KB).
const MAX_FIELD_SECTION: u64 = 64 * 1024;

// QUIC varints (RFC 9000 §16) — used by all hysteria2 stream/datagram framing.

fn varint_len(value: u64) -> usize {
    if value <= 63 {
        1
    } else if value <= 16383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else {
        8
    }
}

fn write_varint(out: &mut Vec<u8>, value: u64) {
    if value <= 63 {
        out.push(value as u8);
    } else if value <= 16383 {
        out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes());
    } else if value <= 1_073_741_823 {
        out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

async fn read_varint_stream(recv: &mut quinn::RecvStream) -> io::Result<u64> {
    let mut first = [0u8; 1];
    read_exact(recv, &mut first).await?;
    let len = 1usize << (first[0] >> 6);
    let mut value = (first[0] & 0x3f) as u64;
    for _ in 1..len {
        let mut b = [0u8; 1];
        read_exact(recv, &mut b).await?;
        value = (value << 8) | b[0] as u64;
    }
    Ok(value)
}

async fn skip_bytes(recv: &mut quinn::RecvStream, mut n: u64) -> io::Result<()> {
    let mut buf = [0u8; 512];
    while n > 0 {
        let chunk = n.min(buf.len() as u64) as usize;
        read_exact(recv, &mut buf[..chunk]).await?;
        n -= chunk as u64;
    }
    Ok(())
}

mod h3;
mod salamander;
#[cfg(test)]
mod tests;

use h3::*;
use salamander::*;

/// Random padding string from the padding alphabet
/// (`protocol/padding.go:7-24`), `max` exclusive like sing's range.
fn random_padding(min: usize, max: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    let n = rng.random_range(min..max);
    (0..n)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

/// Auth request: HEADERS frame for `POST https://hysteria/auth`
/// (`client.go:540-549`, `protocol/http.go:41-45`). `rx_bps` is our receive
/// bandwidth in bits/s; 0 = unset (server falls back to its configured
/// congestion controller instead of brutal).
fn auth_request_frame(password: &str, rx_bps: u64) -> Vec<u8> {
    let padding = random_padding(AUTH_PADDING_MIN, AUTH_PADDING_MAX);
    let section = qpack_encode_request_fields(&[
        (":authority", URL_HOST),
        (":method", "POST"),
        (":path", URL_PATH),
        (":scheme", "https"),
        (HEADER_AUTH, password),
        (HEADER_CC_RX, &rx_bps.to_string()),
        (HEADER_PADDING, padding.as_str()),
        ("content-length", "0"),
    ]);
    h3_headers_frame(&section)
}

/// TCP request bytes for one bi stream (`protocol/proxy.go:69-85`): frame
/// type `0x401`, address as a varint-length-prefixed string, random padding.
fn encode_tcp_request(addr: &str) -> Vec<u8> {
    let padding = random_padding(TCP_PADDING_MIN, TCP_PADDING_MAX);
    let mut out = Vec::with_capacity(8 + addr.len() + padding.len());
    write_varint(&mut out, FRAME_TYPE_TCP_REQUEST);
    write_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    write_varint(&mut out, padding.len() as u64);
    out.extend_from_slice(padding.as_bytes());
    out
}

/// Why a TCP stream handshake failed — distinguishes server-side refusals
/// (healthy connection) from transport failures (cached connection suspect).
#[derive(Debug)]
enum TcpHandshakeError {
    /// The server answered with a non-OK status and an error message.
    Remote(String),
    /// Stream/connection level failure.
    Transport(anyhow::Error),
}

impl std::fmt::Display for TcpHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpHandshakeError::Remote(msg) => write!(f, "Hysteria2: remote error: {msg}"),
            TcpHandshakeError::Transport(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TcpHandshakeError {}

/// Read the TCP response head (`protocol/proxy.go:87-129`): status byte,
/// message vstring, padding. The stream carries raw payload right after.
async fn read_tcp_response(recv: &mut quinn::RecvStream) -> Result<(), TcpHandshakeError> {
    let transport = |e: io::Error| TcpHandshakeError::Transport(e.into());
    let mut status = [0u8; 1];
    read_exact(recv, &mut status).await.map_err(transport)?;
    let message_len = read_varint_stream(recv).await.map_err(transport)?;
    if message_len > MAX_MESSAGE_LENGTH {
        return Err(TcpHandshakeError::Transport(anyhow!(
            "Hysteria2: invalid TCP response message length {message_len}"
        )));
    }
    let mut message = vec![0u8; message_len as usize];
    read_exact(recv, &mut message).await.map_err(transport)?;
    let padding_len = read_varint_stream(recv).await.map_err(transport)?;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(TcpHandshakeError::Transport(anyhow!(
            "Hysteria2: invalid TCP response padding length {padding_len}"
        )));
    }
    skip_bytes(recv, padding_len).await.map_err(transport)?;
    if status[0] != 0 {
        return Err(TcpHandshakeError::Remote(
            String::from_utf8_lossy(&message).into_owned(),
        ));
    }
    Ok(())
}

/// One inbound UDP message (datagram), see `protocol/proxy.go:162-169`.
/// The address is informational; the relay keys sessions by target.
#[derive(Debug)]
struct UdpInbound {
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    #[allow(dead_code)]
    addr: String,
    data: Vec<u8>,
}

/// Decode a UDP message datagram (`protocol/proxy.go:195-221`).
fn decode_udp_message(data: &[u8]) -> Option<UdpInbound> {
    if data.len() < 9 {
        return None;
    }
    let session_id = u32::from_be_bytes(data[0..4].try_into().expect("len checked"));
    let packet_id = u16::from_be_bytes(data[4..6].try_into().expect("len checked"));
    let frag_id = data[6];
    let frag_total = data[7];
    // Address vstring: QUIC varint length + bytes.
    let first = data[8];
    let len_len = 1usize << (first >> 6);
    if data.len() < 8 + len_len {
        return None;
    }
    let mut addr_len = (first & 0x3f) as u64;
    for &b in &data[9..8 + len_len] {
        addr_len = (addr_len << 8) | b as u64;
    }
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        return None;
    }
    let start = 8 + len_len;
    let end = start + addr_len as usize;
    if data.len() < end {
        return None;
    }
    let addr = String::from_utf8(data[start..end].to_vec()).ok()?;
    Some(UdpInbound {
        session_id,
        packet_id,
        frag_id,
        frag_total,
        addr,
        data: data[end..].to_vec(),
    })
}

/// Encode one UDP message datagram (`protocol/proxy.go:180-193`).
fn encode_udp_message(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    addr: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + varint_len(addr.len() as u64) + addr.len() + data.len());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_id);
    out.push(frag_total);
    write_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    out.extend_from_slice(data);
    out
}

/// Build the datagram sequence for one UDP payload, fragmenting like sing's
/// `fragUDPMessage` (`packet.go:87-116`): every fragment repeats the full
/// header (address included — the no-address optimization is marked
/// "not work in hysteria" upstream).
fn fragment_udp_message(
    session_id: u32,
    packet_id: u16,
    addr: &str,
    data: &[u8],
    max_datagram: usize,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let header = 8 + varint_len(addr.len() as u64) + addr.len();
    if header + data.len() <= max_datagram {
        return Ok(vec![encode_udp_message(
            session_id, packet_id, 0, 1, addr, data,
        )]);
    }
    let chunk = max_datagram.saturating_sub(header);
    if chunk == 0 {
        anyhow::bail!("datagram MTU {max_datagram} too small for the UDP message header");
    }
    let frag_total = data.len().div_ceil(chunk);
    if frag_total > u8::MAX as usize {
        anyhow::bail!("UDP payload {} bytes needs too many fragments", data.len());
    }
    let mut out = Vec::with_capacity(frag_total);
    for (frag_id, piece) in data.chunks(chunk).enumerate() {
        out.push(encode_udp_message(
            session_id,
            packet_id,
            frag_id as u8,
            frag_total as u8,
            addr,
            piece,
        ));
    }
    Ok(out)
}

type SessionMap = Arc<parking_lot::Mutex<HashMap<u32, mpsc::Sender<UdpInbound>>>>;

/// Per-session inbound queue depth. UDP semantics: a full queue drops the
/// datagram rather than queueing without bound.
const UDP_SESSION_QUEUE_CAP: usize = 256;

/// Per-QUIC-connection protocol state (demux maps, counters, reaper task).
struct Hy2ConnState {
    conn: quinn::Connection,
    udp_disabled: bool,
    sessions: SessionMap,
    next_session: AtomicU32,
    /// Number of open TCP streams + UDP bridges on this connection.
    open: Arc<AtomicUsize>,
    /// Last activity (unix seconds) for the idle-connection reaper.
    last_activity: Arc<AtomicU64>,
    /// H3 client preface streams (control + QPACK encoder/decoder). Held
    /// open for the life of the connection: dropping the send half finishes
    /// the stream, and closing a critical H3 stream is a connection error.
    _preface: (quinn::SendStream, quinn::SendStream, quinn::SendStream),
}

impl QuicConnState for Hy2ConnState {
    fn touch(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
    }

    fn open_counter(&self) -> &Arc<AtomicUsize> {
        &self.open
    }
}

impl Hy2ConnState {
    fn new(
        conn: quinn::Connection,
        udp_disabled: bool,
        preface: (quinn::SendStream, quinn::SendStream, quinn::SendStream),
    ) -> Self {
        let sessions: SessionMap = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let state = Self {
            conn: conn.clone(),
            udp_disabled,
            sessions: Arc::clone(&sessions),
            next_session: AtomicU32::new(0),
            open: Arc::new(AtomicUsize::new(0)),
            last_activity: Arc::new(AtomicU64::new(now_secs())),
            _preface: preface,
        };
        if !udp_disabled {
            // Inbound QUIC datagrams demultiplexed by session id
            // (`client_packet.go:5-19`).
            tokio::spawn(async move {
                loop {
                    let Ok(data) = conn.read_datagram().await else {
                        break;
                    };
                    let Some(msg) = decode_udp_message(&data) else {
                        continue;
                    };
                    let tx = sessions.lock().get(&msg.session_id).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.try_send(msg); // drop on a full queue (UDP semantics)
                    } else {
                        debug!(
                            session_id = msg.session_id,
                            "Hysteria2 UDP: datagram for unknown session dropped"
                        );
                    }
                }
                // Connection died: drop all session senders so bridges end.
                sessions.lock().clear();
            });
        }
        crate::quic::spawn_conn_reaper(
            state.conn.clone(),
            Arc::downgrade(&state.open),
            Arc::downgrade(&state.last_activity),
            KEEP_ALIVE_INTERVAL,
            CONN_IDLE_TIMEOUT,
            None,
        );
        state
    }

    fn alloc_session(&self) -> u32 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }
}

struct Hy2Client {
    quic: QuicClient<Hy2ConnState>,
    password: String,
    /// Receive bandwidth advertised in the auth exchange, bits/s (0 = unset).
    rx_bps: u64,
}

#[async_trait]
impl crate::runtime::QuicRuntimeClient for Hy2Client {
    fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }

    async fn force_close(&self) {
        self.quic.force_close().await;
    }
}

impl Hy2Client {
    async fn connection(
        &self,
        connect_timeout: Duration,
    ) -> anyhow::Result<(quinn::Connection, Arc<Hy2ConnState>)> {
        let password = self.password.clone();
        let rx_bps = self.rx_bps;
        self.quic
            .connection_with(connect_timeout, move |conn| async move {
                authenticate(&conn, &password, rx_bps, connect_timeout).await
            })
            .await
    }
}

/// Hysteria2 connection setup: send the H3 client preface, then authenticate
/// with the `POST https://hysteria/auth` exchange (`client.go:533-605`).
/// Runs inside the single-flight critical section of `QuicClient`.
async fn authenticate(
    conn: &quinn::Connection,
    password: &str,
    rx_bps: u64,
    timeout: Duration,
) -> anyhow::Result<Hy2ConnState> {
    tokio::time::timeout(timeout, async {
        // Client preface: control stream + SETTINGS, QPACK encoder/decoder
        // streams (type byte only — no dynamic table instructions).
        let mut control = conn
            .open_uni()
            .await
            .context("Hysteria2: open control stream")?;
        control
            .write_all(&client_preface())
            .await
            .context("Hysteria2: send SETTINGS")?;
        let mut qpack_enc = conn
            .open_uni()
            .await
            .context("Hysteria2: open QPACK encoder stream")?;
        qpack_enc
            .write_all(&[H3_STREAM_QPACK_ENCODER as u8])
            .await
            .context("Hysteria2: QPACK encoder stream preface")?;
        let mut qpack_dec = conn
            .open_uni()
            .await
            .context("Hysteria2: open QPACK decoder stream")?;
        qpack_dec
            .write_all(&[H3_STREAM_QPACK_DECODER as u8])
            .await
            .context("Hysteria2: QPACK decoder stream preface")?;

        // Auth request on a bi stream; the response HEADERS carry the result.
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("Hysteria2: open auth stream")?;
        send.write_all(&auth_request_frame(password, rx_bps))
            .await
            .context("Hysteria2: send auth request")?;
        send.finish().context("Hysteria2: finish auth request")?;
        let headers = read_h3_response_headers(&mut recv)
            .await
            .context("Hysteria2: read auth response")?;
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        let status: u16 = header(":status").and_then(|v| v.parse().ok()).unwrap_or(0);
        if status != STATUS_AUTH_OK {
            anyhow::bail!("Hysteria2: authentication failed, status code: {status}");
        }
        let udp_enabled = header(HEADER_UDP) == Some("true");
        // Dropping the receive half issues STOP_SENDING for the unread
        // response body — what quic-go's http3 client does on
        // `response.Body.Close()` after a successful auth.
        Ok(Hy2ConnState::new(
            conn.clone(),
            !udp_enabled,
            (control, qpack_enc, qpack_dec),
        ))
    })
    .await
    .map_err(|_| anyhow!("Hysteria2: authentication timed out"))?
}

/// `host:port` address string for the wire (domain preferred; IPv6 gets
/// brackets via `SocketAddr`'s `Display`).
fn target_string(target: SocketAddr, target_domain: Option<&str>) -> String {
    match target_domain {
        Some(domain) => format!("{domain}:{}", target.port()),
        None => target.to_string(),
    }
}

/// Hysteria2 proxy handler (QUIC). Stateless: the per-server client (and
/// its shared QUIC connection) lives in the node's generation runtime.
#[derive(Debug, Default, Clone)]
pub struct Hysteria2Handler;

impl Hysteria2Handler {
    pub fn new() -> Self {
        Self
    }

    /// Resolve the effective authentication password (`hy2_auth`, falling
    /// back to `password`).
    fn resolve_password(node: &Node) -> &str {
        node.hy2_auth
            .as_deref()
            .unwrap_or_else(|| node.password.as_deref().unwrap_or(""))
    }

    async fn build_client(&self, node: &Node) -> anyhow::Result<Arc<Hy2Client>> {
        let password = Self::resolve_password(node);
        let obfs = node.hy2_obfs.as_deref().filter(|s| !s.is_empty());
        // Receive bandwidth for the auth header, bits/s (0 = unset).
        let rx_bps = u64::from(node.hy2_down_mbps.unwrap_or(0)) * 1_000_000;
        // Port hopping (`mport`/`mhop`): destination port rotates among the
        // list every interval (default 30s, official client parity).
        let hop = node
            .hy2_port_hopping
            .as_deref()
            .and_then(parse_port_hopping)
            .map(|ports| {
                (
                    ports,
                    Duration::from_secs(node.hy2_hop_interval.unwrap_or(30).max(1)),
                )
            });
        let server_name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
        // ALPN "h3" (hysteria2 runs its auth over HTTP/3, `client.go:100-102`).
        // With `hy2_up_mbps` the send side runs a fixed-rate brutal sender;
        // otherwise BBR — sing-quic's default when no bandwidth is
        // configured (`client.go:580-588`).
        let factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
            match node.hy2_up_mbps {
                Some(mbps) if mbps > 0 => Arc::new(crate::quic::BrutalConfig::from_bps(
                    u64::from(mbps) * 1_000_000,
                )),
                _ => crate::quic::congestion_factory(Some("bbr")),
            };
        let config = crate::quic::client_config(
            node,
            &[b"h3"],
            crate::quic::QuicClientOptions {
                congestion: Some(factory),
                keep_alive: Some(KEEP_ALIVE_INTERVAL),
                // Download throughput is capped by our advertised receive
                // windows (window/RTT): quinn's 1.25 MiB stream default
                // tops out around 2 Gbps on a LAN. Match the TUIC
                // defaults (8 MiB stream / 32 MiB conn).
                stream_receive_window: node.hy2_init_stream_recv_window.or(Some(8 << 20)),
                conn_receive_window: node.hy2_init_conn_recv_window.or(Some(32 << 20)),
                disable_mtu_discovery: node.hy2_disable_mtu_discovery == Some(true),
                max_udp_payload_size: node.quic_mtu,
            },
        )
        .await?;
        let quic = QuicClient::new(node.host().to_string(), node.port, server_name, config);
        let mtu = node.quic_mtu.unwrap_or(1252);
        let quic = quic.with_max_udp_payload_size(mtu);
        let quic = match (obfs, hop) {
            (None, None) => quic,
            (obfs, hop) => quic.with_endpoint_factory(hy2_endpoint_factory(
                obfs.map(|p| Arc::from(p.as_bytes())),
                hop,
                mtu,
            )),
        };
        Ok(Arc::new(Hy2Client {
            quic,
            password: password.to_string(),
            rx_bps,
        }))
    }

    async fn client_for_runtime(
        &self,
        runtime: &crate::runtime::NodeRuntime,
    ) -> anyhow::Result<Arc<Hy2Client>> {
        let crate::runtime::ProtocolRuntime::Quic(quic_runtime) = &runtime.runtime else {
            anyhow::bail!("Hysteria2 runtime is not QUIC-owned");
        };
        quic_runtime
            .client(|| self.build_client(runtime.node.as_ref()))
            .await
    }
}

#[async_trait]
impl WarmableOutbound for Hysteria2Handler {
    async fn warm_udp(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: Duration,
    ) -> anyhow::Result<super::UdpWarmStatus> {
        let client = self.client_for_runtime(&runtime).await?;
        let already_ready = client.quic.has_live_connection().await;
        let (_, state) = client.connection(connect_timeout).await?;
        if state.udp_disabled {
            anyhow::bail!("Hysteria2: UDP disabled by server");
        }
        Ok(if already_ready {
            super::UdpWarmStatus::AlreadyReady
        } else {
            super::UdpWarmStatus::Ready
        })
    }
}

impl Hysteria2Handler {
    async fn dial_via_client(
        &self,
        client: Arc<Hy2Client>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = target_string(target, target_domain);
        if addr.len() as u64 > MAX_ADDRESS_LENGTH {
            anyhow::bail!("Hysteria2: target address too long");
        }
        let stream = crate::quic::dial_quic_stream(
            &client.quic,
            |timeout| {
                let client = Arc::clone(&client);
                async move { client.connection(timeout).await }
            },
            connect_timeout,
            move |conn| {
                let addr = addr.clone();
                async move {
                    let handshake: Result<_, TcpHandshakeError> = async {
                        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
                            TcpHandshakeError::Transport(anyhow!("Hysteria2: open stream: {e}"))
                        })?;
                        send.write_all(&encode_tcp_request(&addr))
                            .await
                            .map_err(|e| {
                                TcpHandshakeError::Transport(anyhow!(
                                    "Hysteria2: send TCP request: {e}"
                                ))
                            })?;
                        read_tcp_response(&mut recv).await?;
                        Ok((send, recv))
                    }
                    .await;
                    handshake.map_err(anyhow::Error::from)
                }
            },
            // The server refusing a target is not a connection problem.
            |e| {
                !matches!(
                    e.downcast_ref::<TcpHandshakeError>(),
                    Some(TcpHandshakeError::Remote(_))
                )
            },
            "Hysteria2",
        )
        .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    async fn udp_transport_via_client(
        &self,
        client: Arc<Hy2Client>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (conn, state) = client.connection(connect_timeout).await?;
        if state.udp_disabled {
            anyhow::bail!("Hysteria2: UDP disabled by server");
        }
        let max_datagram = conn
            .max_datagram_size()
            .ok_or_else(|| anyhow!("Hysteria2: peer does not support QUIC datagrams"))?;
        state.touch();
        let session_id = state.alloc_session();
        let addr = target_string(target, target_domain);
        if addr.len() as u64 > MAX_ADDRESS_LENGTH {
            anyhow::bail!("Hysteria2: target address too long");
        }
        let (tx, rx) = mpsc::channel::<UdpInbound>(UDP_SESSION_QUEUE_CAP);
        state.sessions.lock().insert(session_id, tx);
        state.open.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(Hy2UdpTransport {
            state,
            session_id,
            packet_id: AtomicU16::new(0),
            rx: tokio::sync::Mutex::new(rx),
            defrag: tokio::sync::Mutex::new(Defragmenter::new()),
            addr,
            max_datagram,
            target,
        }))
    }
}

#[async_trait]
impl TcpOutbound for Hysteria2Handler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let client = self.build_client(node).await?;
        self.dial_via_client(client, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let client = self.client_for_runtime(&runtime).await?;
        self.dial_via_client(client, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_with_tcp(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _tcp: tokio::net::TcpStream,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!("Hysteria2 runs over QUIC; a bare TCP connection cannot be reused")
    }
}

#[async_trait]
impl PacketOutbound for Hysteria2Handler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let client = self.build_client(node).await?;
        self.udp_transport_via_client(client, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let client = self.client_for_runtime(&runtime).await?;
        self.udp_transport_via_client(client, target, target_domain, connect_timeout)
            .await
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<super::PreparedUdpTransport> {
        self.dial_udp_transport_runtime(runtime, target, target_domain, connect_timeout)
            .await
            .map(super::PreparedUdpTransport::ready)
    }
}

#[async_trait]
impl ProbeableOutbound for Hysteria2Handler {
    async fn test_connectivity(&self, node: &Node) -> bool {
        match self.build_client(node).await {
            Ok(client) => client.connection(Duration::from_secs(5)).await.is_ok(),
            Err(e) => {
                debug!(
                    "Hysteria2 connectivity test failed for {}: {}",
                    node.name, e
                );
                false
            }
        }
    }
}

/// Framed UDP transport over the shared Hysteria2 QUIC connection: UDP
/// message datagrams go straight onto the connection and inbound datagrams
/// arrive through the session demux queue.
struct Hy2UdpTransport {
    state: Arc<Hy2ConnState>,
    session_id: u32,
    packet_id: AtomicU16,
    rx: tokio::sync::Mutex<mpsc::Receiver<UdpInbound>>,
    defrag: tokio::sync::Mutex<Defragmenter>,
    addr: String,
    max_datagram: usize,
    target: SocketAddr,
}

impl std::fmt::Debug for Hy2UdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hy2UdpTransport")
            .field("session_id", &self.session_id)
            .field("target", &self.target)
            .finish()
    }
}

impl Drop for Hy2UdpTransport {
    fn drop(&mut self) {
        self.state.sessions.lock().remove(&self.session_id);
        self.state.open.fetch_sub(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl PacketTransport for Hy2UdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_UDP_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 datagram too large",
            ));
        }
        self.state.touch();
        let packet_id = self
            .packet_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let packets = fragment_udp_message(
            self.session_id,
            packet_id,
            &self.addr,
            data,
            self.max_datagram,
        )
        .map_err(io::Error::other)?;
        for packet in packets {
            self.state
                .conn
                .send_datagram(bytes::Bytes::from(packet))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let msg = self.rx.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "hysteria2 connection closed",
                )
            })?;
            let complete =
                self.defrag
                    .lock()
                    .await
                    .feed(msg.packet_id, msg.frag_id, msg.frag_total, msg.data);
            if let Some(data) = complete {
                if data.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "hysteria2 packet exceeds buffer",
                    ));
                }
                buf[..data.len()].copy_from_slice(&data);
                return Ok((data.len(), self.target));
            }
        }
    }
}
