//! Packet sniffer pool for QUIC/UDP domain extraction.
//!
//! Manages per-flow sniffing sessions for QUIC Initial packets to extract
//! SNI (Server Name Indication) from UDP traffic. Initial packets are
//! decrypted per RFC 9001/RFC 9369 (see [`crate::control::quic`]) and their
//! CRYPTO frames reassembled per session into the TLS ClientHello stream.
//! Uses a negative cache for flows that failed to yield a domain, avoiding
//! repeated sniffing attempts for non-QUIC traffic.
//!
//! Mirrors the Go `packet_sniffer_pool.go` (1001L).

use crate::control::quic::{self, CryptoReassembly};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::debug;

/// How long a sniffer session stays alive waiting for QUIC handshake completion.
const SNIFFER_TTL: Duration = Duration::from_secs(5);
/// How often the janitor cleans up expired sessions.
const JANITOR_INTERVAL: Duration = Duration::from_millis(250);
/// How many consecutive no-SNI attempts before marking DCID as failed.
const NO_SNI_THRESHOLD: u32 = 4;
/// How long sniffing is disabled after reaching the no-SNI threshold.
const NO_SNI_BYPASS_TTL: Duration = Duration::from_secs(1);

/// Outcome of feeding one datagram to the QUIC Initial sniffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicSniffOutcome {
    /// Not a parseable/decryptable QUIC Initial (garbage, unsupported
    /// version, AEAD failure), or sniffing was skipped on a negative-cache
    /// hit — the flow is not provably QUIC.
    NotQuic,
    /// A genuine, successfully decrypted QUIC Initial whose ClientHello
    /// yielded no usable SNI (yet): a multi-packet ClientHello still waiting
    /// for CRYPTO fragments, a complete ClientHello without SNI, or an
    /// unparsable one.  The flow is provably QUIC.
    ValidNoDomain,
    /// SNI extracted from a decrypted Initial.
    Domain(String),
}

impl QuicSniffOutcome {
    /// Whether the datagram was confirmed to be a genuine QUIC Initial.
    /// Only confirmed flows may be considered for drop-and-reinject
    /// offload — a non-QUIC flow has no retransmission guarantee, so its
    /// first datagram must never be dropped.
    pub fn is_quic_confirmed(&self) -> bool {
        !matches!(self, Self::NotQuic)
    }

    /// The sniffed SNI, if extraction succeeded.
    pub fn into_domain(self) -> Option<String> {
        match self {
            Self::Domain(domain) => Some(domain),
            _ => None,
        }
    }
}

/// A key identifying a QUIC flow family: (src, dst).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketSnifferKey {
    pub src_ip: [u8; 16],
    pub src_port: u16,
    pub dst_ip: [u8; 16],
    pub dst_port: u16,
}

impl PacketSnifferKey {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        match src.ip() {
            std::net::IpAddr::V4(ip) => {
                src_ip[10] = 0xff;
                src_ip[11] = 0xff;
                src_ip[12..16].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => src_ip.copy_from_slice(&ip.octets()),
        }
        match dst.ip() {
            std::net::IpAddr::V4(ip) => {
                dst_ip[10] = 0xff;
                dst_ip[11] = 0xff;
                dst_ip[12..16].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => dst_ip.copy_from_slice(&ip.octets()),
        }
        Self {
            src_ip,
            src_port: src.port(),
            dst_ip,
            dst_port: dst.port(),
        }
    }
}

/// State for a single sniffer session.
struct SnifferSession {
    /// The sniffed domain (if extraction succeeded).
    domain: Option<String>,
    /// Number of packets processed for this session.
    packets_seen: u32,
    /// Number of decrypted packets whose ClientHello was unusable.
    no_sni_count: u32,
    /// Number of datagrams that failed QUIC Initial parsing/decryption.
    error_count: u32,
    /// CRYPTO stream reassembly for ClientHellos spanning multiple
    /// Initial packets.
    crypto: CryptoReassembly,
    /// Whether this session has been finalized.
    done: bool,
    /// When this session expires.
    expires_at: Instant,
}

impl SnifferSession {
    fn new() -> Self {
        Self {
            domain: None,
            packets_seen: 0,
            no_sni_count: 0,
            error_count: 0,
            crypto: CryptoReassembly::default(),
            done: false,
            expires_at: Instant::now() + SNIFFER_TTL,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    fn should_bypass(&self) -> bool {
        self.no_sni_count >= NO_SNI_THRESHOLD
    }
}

/// Entry in the failed DCID negative cache.
#[derive(Debug, Clone)]
struct FailedDcidEntry {
    #[allow(dead_code)]
    reason: DcidFailureReason,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DcidFailureReason {
    SoftBypass,
    DecryptFailure,
}

/// Pool of packet sniffers with DCID negative caching.
pub struct PacketSnifferPool {
    sessions: Mutex<HashMap<PacketSnifferKey, SnifferSession>>,
    failed_dcids: Mutex<HashMap<PacketSnifferKey, FailedDcidEntry>>,
}

impl PacketSnifferPool {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            failed_dcids: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a DCID is in the failed cache (should skip sniffing).
    pub fn is_dcid_failed(&self, key: &PacketSnifferKey) -> bool {
        let cache = self.failed_dcids.lock().unwrap();
        if let Some(entry) = cache.get(key)
            && Instant::now() < entry.expires_at
        {
            return true;
        }
        false
    }

    /// Record a failed DCID with a soft bypass duration.
    pub fn mark_dcid_failed_soft(&self, key: PacketSnifferKey) {
        let mut cache = self.failed_dcids.lock().unwrap();
        cache.insert(
            key,
            FailedDcidEntry {
                reason: DcidFailureReason::SoftBypass,
                expires_at: Instant::now() + NO_SNI_BYPASS_TTL,
            },
        );
        if cache.len() > 16384 {
            cache.retain(|_, v| Instant::now() < v.expires_at);
        }
    }

    /// Record a failed DCID due to decrypt failure (longer bypass).
    pub fn mark_dcid_failed_decrypt(&self, key: PacketSnifferKey) {
        let mut cache = self.failed_dcids.lock().unwrap();
        cache.insert(
            key,
            FailedDcidEntry {
                reason: DcidFailureReason::DecryptFailure,
                expires_at: Instant::now() + Duration::from_secs(30),
            },
        );
    }

    /// Feed a UDP datagram (expected to carry QUIC Initial packet(s)) to the
    /// sniffer for a flow.  Returns whether the datagram was confirmed to be
    /// a genuine QUIC Initial, carrying the SNI hostname when extraction
    /// succeeded — see [`QuicSniffOutcome`].
    pub fn feed_quic_initial(&self, key: PacketSnifferKey, data: &[u8]) -> QuicSniffOutcome {
        if self.is_dcid_failed(&key) {
            return QuicSniffOutcome::NotQuic;
        }

        // Decrypt the Initial packet(s) first (stateless, no lock needed).
        let fragments = quic::decrypt_initial_datagram(data);

        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.entry(key).or_insert_with(SnifferSession::new);

        if session.done {
            return session
                .domain
                .clone()
                .map(QuicSniffOutcome::Domain)
                .unwrap_or(QuicSniffOutcome::ValidNoDomain);
        }

        session.packets_seen += 1;

        let fragments = match fragments {
            Ok(fragments) => fragments,
            Err(err) => {
                // Not QUIC, an unsupported version, or decryption failed:
                // this flow will most likely never yield a domain.
                session.error_count += 1;
                let failed = session.error_count >= NO_SNI_THRESHOLD;
                if failed {
                    session.done = true;
                }
                drop(sessions);
                if failed {
                    debug!("QUIC sniffing bypassed after repeated decrypt failures: {err:?}");
                    self.mark_dcid_failed_decrypt(key);
                }
                return QuicSniffOutcome::NotQuic;
            }
        };

        for (offset, data) in fragments {
            session.crypto.insert(offset, data);
        }

        let parse = if session.crypto.is_overflowed() {
            quic::ClientHelloParse::Invalid
        } else {
            quic::parse_client_hello(session.crypto.assembled())
        };

        match parse {
            quic::ClientHelloParse::Complete(Some(domain)) => {
                session.domain = Some(domain.clone());
                session.done = true;
                debug!(
                    "QUIC SNI extracted: {} (packets_seen={})",
                    domain, session.packets_seen
                );
                QuicSniffOutcome::Domain(domain)
            }
            quic::ClientHelloParse::Complete(None) => {
                // Complete ClientHello without SNI: this flow never yields
                // a domain.
                session.done = true;
                drop(sessions);
                self.mark_dcid_failed_soft(key);
                debug!("QUIC ClientHello carried no SNI; flow bypassed");
                QuicSniffOutcome::ValidNoDomain
            }
            quic::ClientHelloParse::Incomplete => {
                // The ClientHello spans multiple Initial packets; wait for
                // the remaining CRYPTO fragments.
                QuicSniffOutcome::ValidNoDomain
            }
            quic::ClientHelloParse::Invalid => {
                session.no_sni_count += 1;
                let should_bypass = session.should_bypass();
                if should_bypass {
                    session.done = true;
                }
                drop(sessions);
                if should_bypass {
                    self.mark_dcid_failed_soft(key);
                    debug!("QUIC DCID marked failed after no-SNI threshold");
                }
                QuicSniffOutcome::ValidNoDomain
            }
        }
    }

    /// Run a janitor cycle: remove expired sessions.
    pub fn janitor_cycle(&self) -> usize {
        let mut sessions = self.sessions.lock().unwrap();
        let before = sessions.len();
        sessions.retain(|_, s| !s.is_expired());
        let removed = before - sessions.len();
        if removed > 0 {
            debug!(
                "Packet sniffer janitor removed {} expired sessions",
                removed
            );
        }

        let mut dcids = self.failed_dcids.lock().unwrap();
        dcids.retain(|_, v| Instant::now() < v.expires_at);

        removed
    }

    /// Spawn a background janitor task.
    pub fn spawn_janitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(JANITOR_INTERVAL).await;
                pool.janitor_cycle();
            }
        })
    }
}

impl Default for PacketSnifferPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::quic::{QUIC_VERSION_1, test_utils};

    fn test_key() -> PacketSnifferKey {
        PacketSnifferKey::new(
            "10.0.0.1:12345".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        )
    }

    /// A datagram that looks like a QUIC Initial header but carries a
    /// garbage payload, so AEAD decryption always fails.
    fn garbage_initial() -> Vec<u8> {
        let mut data = vec![0xC0];
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.push(8);
        data.extend_from_slice(b"dcid0001");
        data.push(0); // SCID
        data.push(0); // Token
        data.push(0x40 + 20);
        data.push(20);
        data.extend_from_slice(&[0u8; 20]);
        data
    }

    /// RFC 9001 A.2 vector end-to-end: the protected client Initial
    /// decrypts to a ClientHello for "example.com".
    #[test]
    fn test_pool_extracts_sni_rfc9001_vector() {
        let pool = PacketSnifferPool::new();
        let key = test_key();
        let packet = test_utils::rfc9001_client_initial();

        let result = pool.feed_quic_initial(key, &packet);
        assert_eq!(result, QuicSniffOutcome::Domain("example.com".into()));
        assert!(result.is_quic_confirmed());

        // The extracted domain is cached on the completed session.
        let result = pool.feed_quic_initial(key, &packet);
        assert_eq!(result, QuicSniffOutcome::Domain("example.com".into()));
        assert!(!pool.is_dcid_failed(&key));
    }

    /// A ClientHello split across two Initial packets (arriving out of
    /// order) is reassembled before the SNI is extracted.
    #[test]
    fn test_pool_fragmented_client_hello_out_of_order() {
        let pool = PacketSnifferPool::new();
        let key = test_key();
        let hello = test_utils::build_client_hello(Some("quic.example.org"));
        let split = 40;
        let pkt0 = test_utils::protect_initial_packet(
            b"dcid1234",
            b"",
            QUIC_VERSION_1,
            0,
            1,
            &test_utils::wrap_crypto_frame(0, &hello[..split]),
        );
        let pkt1 = test_utils::protect_initial_packet(
            b"dcid1234",
            b"",
            QUIC_VERSION_1,
            1,
            1,
            &test_utils::wrap_crypto_frame(split as u64, &hello[split..]),
        );

        // Second fragment first: buffered, nothing to parse yet — but the
        // Initial decrypted, so the flow is already confirmed QUIC.
        let pending = pool.feed_quic_initial(key, &pkt1);
        assert_eq!(pending, QuicSniffOutcome::ValidNoDomain);
        assert!(pending.is_quic_confirmed());
        assert!(!pool.is_dcid_failed(&key));
        // First fragment completes the ClientHello.
        let result = pool.feed_quic_initial(key, &pkt0);
        assert_eq!(result, QuicSniffOutcome::Domain("quic.example.org".into()));
    }

    /// A complete ClientHello without an SNI extension bypasses the flow
    /// immediately (it can never yield a domain).
    #[test]
    fn test_pool_client_hello_without_sni_bypasses() {
        let pool = PacketSnifferPool::new();
        let key = test_key();
        let hello = test_utils::build_client_hello(None);
        let packet = test_utils::protect_initial_packet(
            b"dcid1234",
            b"",
            QUIC_VERSION_1,
            0,
            1,
            &test_utils::wrap_crypto_frame(0, &hello),
        );

        // Decryption succeeded, so the flow is confirmed QUIC even though
        // it can never yield a domain.
        let outcome = pool.feed_quic_initial(key, &packet);
        assert_eq!(outcome, QuicSniffOutcome::ValidNoDomain);
        assert!(outcome.is_quic_confirmed());
        assert!(pool.is_dcid_failed(&key));
    }

    #[test]
    fn test_sniffer_pool_basic() {
        let pool = PacketSnifferPool::new();
        let key = test_key();
        assert!(!pool.is_dcid_failed(&key));

        let data = garbage_initial();

        let result = pool.feed_quic_initial(key, &data);
        // Decryption fails on the garbage payload: not provably QUIC.
        assert_eq!(result, QuicSniffOutcome::NotQuic);
        assert!(!result.is_quic_confirmed());
        assert!(!pool.is_dcid_failed(&key));

        for _ in 0..4 {
            pool.feed_quic_initial(key, &data);
        }
        assert!(pool.is_dcid_failed(&key));
    }
}
