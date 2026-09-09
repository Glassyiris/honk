use super::*;
use crate::dns::cache::DnsCache;
use crate::dns::routing::DnsRouter;
use honk_config::dns::{DnsRouting, DnsRule};

use std::sync::atomic::{AtomicUsize, Ordering};

fn test_cache() -> Arc<Mutex<DnsCache>> {
    Arc::new(Mutex::new(DnsCache::new(100)))
}

fn test_router() -> Arc<DnsRouter> {
    Arc::new(
        DnsRouter::new(&DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .expect("test router"),
    )
}

#[cfg(target_os = "linux")]
#[test]
fn asis_socket_tolerates_only_permission_denied_mark_failure() {
    // Given
    let destination = SocketAddr::from(([127, 0, 0, 1], 53));

    // When
    let socket = new_asis_socket_with_mark(destination, |_| {
        honk_outbound::util::set_mark_result_best_effort(Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected EPERM",
        )))
    });

    // Then
    assert!(socket.is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn asis_socket_propagates_non_permission_mark_failure_as_typed_error() {
    // Given
    let destination = SocketAddr::from(([127, 0, 0, 1], 53));

    // When
    let error = new_asis_socket_with_mark(destination, |_| {
        honk_outbound::util::set_mark_result_best_effort(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "injected EINVAL",
        )))
    })
    .expect_err("non-EPERM mark failure");

    // Then
    assert!(matches!(error, AsIsExchangeError::BypassMark { .. }));
}

/// Build an A-record response for example.com with a given IP and TTL.
fn make_a_response(ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let ttl_bytes = ttl.to_be_bytes();
    vec![
        0x00,
        0x00, // ID (matches the query built by build_dns_query)
        0x81,
        0x80, // Flags: QR=1, RD=1, RA=1
        0x00,
        0x01, // QDCOUNT
        0x00,
        0x01, // ANCOUNT
        0x00,
        0x00, // NSCOUNT
        0x00,
        0x00, // ARCOUNT
        0x07,
        b'e',
        b'x',
        b'a',
        b'm',
        b'p',
        b'l',
        b'e',
        0x03,
        b'c',
        b'o',
        b'm',
        0x00,
        0x00,
        0x01, // QTYPE A
        0x00,
        0x01, // QCLASS IN
        0xc0,
        0x0c, // NAME pointer to offset 12
        0x00,
        0x01, // TYPE A
        0x00,
        0x01, // CLASS IN
        ttl_bytes[0],
        ttl_bytes[1],
        ttl_bytes[2],
        ttl_bytes[3], // TTL
        0x00,
        0x04, // RDLENGTH
        ip[0],
        ip[1],
        ip[2],
        ip[3], // RDATA
    ]
}

/// Build an A-record query for example.com (same as what prefetch uses).
fn make_a_query() -> Vec<u8> {
    build_dns_query("example.com", 1)
}

/// Build an NXDOMAIN response preserving the query question and carrying an
/// authority SOA whose TTL and MINIMUM determine the negative cache lifetime.
fn make_nxdomain_response(query: &[u8], soa_ttl: u32, soa_minimum: u32) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2] = 0x81;
    response[3] = 0x83;
    response[6..8].copy_from_slice(&0_u16.to_be_bytes()); // ANCOUNT
    response[8..10].copy_from_slice(&1_u16.to_be_bytes()); // NSCOUNT
    response[10..12].copy_from_slice(&0_u16.to_be_bytes()); // ARCOUNT

    response.extend_from_slice(&[0xc0, 0x0c]); // NAME pointer to qname
    response.extend_from_slice(&[0x00, 0x06, 0x00, 0x01]); // SOA, IN
    response.extend_from_slice(&soa_ttl.to_be_bytes());
    response.extend_from_slice(&22_u16.to_be_bytes());
    response.extend_from_slice(&[0, 0]); // Root MNAME and RNAME, followed by five u32 fields.
    for value in [1_u32, 7200, 3600, 1_209_600, soa_minimum] {
        response.extend_from_slice(&value.to_be_bytes());
    }
    response
}

struct MockUpstream {
    response: Vec<u8>,
    call_count: AtomicUsize,
}

impl MockUpstream {
    fn new(response: Vec<u8>) -> Self {
        Self {
            response,
            call_count: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl DnsUpstreamPool for MockUpstream {
    async fn query(&self, _upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(self.response.clone())
    }
}

struct GatedUpstream {
    response: Vec<u8>,
    call_count: AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl DnsUpstreamPool for GatedUpstream {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.release.notified().await;
        Ok(self.response.clone())
    }
}

enum RefreshFenceLater {
    Response(Vec<u8>),
    Error,
}

struct RefreshFenceUpstream {
    initial: Vec<u8>,
    refreshed: Vec<u8>,
    later: RefreshFenceLater,
    call_count: AtomicUsize,
    refresh_entered: tokio::sync::Notify,
    refresh_release: tokio::sync::Semaphore,
}

#[async_trait]
impl DnsUpstreamPool for RefreshFenceUpstream {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        let call = self.call_count.fetch_add(1, Ordering::SeqCst);
        if call == 1 {
            self.refresh_entered.notify_one();
            self.refresh_release
                .acquire()
                .await
                .expect("refresh release")
                .forget();
        }
        match call {
            0 => Ok(self.initial.clone()),
            1 => Ok(self.refreshed.clone()),
            _ => match &self.later {
                RefreshFenceLater::Response(response) => Ok(response.clone()),
                RefreshFenceLater::Error => anyhow::bail!("foreground upstream down"),
            },
        }
    }
}
