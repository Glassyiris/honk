//! DNS Controller — intercepts TPROXY DNS traffic and routes it through
//! the DNS forwarder, updating eBPF domain routing on resolution.
//!
//! ## Features
//!
//! - DNS query interception (UDP + TCP)
//! - Singleflight deduplication for concurrent identical queries
//! - Async BPF cache update channel (non-blocking)
//! - Periodic route refresh worker
//! - Concurrency limit with graceful SERVFAIL degradation
//!
//! Go ref: `dns_control.go` (2943L)

use crate::dns::forwarder::DnsForwarder;
use crate::ebpf::EbpfBackend;
#[cfg(test)]
use crate::group::GroupManager;
use crate::routing::Router;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{RwLock, Semaphore};
use tracing::debug;

#[cfg(test)]
struct NoopRuntimeTransport;

#[cfg(test)]
#[async_trait::async_trait]
impl crate::dns::runtime::RuntimeTransport for NoopRuntimeTransport {
    async fn close(&self) {}
}

/// Max concurrent in-flight DNS queries. Sized like dae's (16384 @ ~4KB
/// each) but conservative: 2048 ≈ 8MB of in-flight state, comfortably
/// covering thousands of QPS before degradation. Over the limit the answer
/// is REFUSED, not SERVFAIL — SERVFAIL invites client retry storms, REFUSED
/// says "busy, back off".
const DEFAULT_MAX_CONCURRENT_QUERIES: usize = 2048;

/// DNS Controller — intercepts TPROXY DNS traffic and forwards it through
/// the DNS forwarding engine with proactive eBPF route updates.
pub struct DnsController {
    forwarder: Arc<RwLock<DnsForwarder>>,
    runtime_provider: Arc<crate::dns::runtime::DnsServiceProvider>,
    routing_projection: Arc<crate::dns::projection::RoutingProjection>,
    concurrency_limit: Semaphore,
}

impl DnsController {
    #[cfg(test)]
    pub fn new(
        forwarder: Arc<DnsForwarder>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        router: Arc<RwLock<Router>>,
    ) -> Self {
        let config = honk_config::Config::default();
        let runtime_router = Arc::new(
            Router::new(&config.routing.rules, &config.routing.default_outbound)
                .unwrap_or_else(|_| Router::new(&[], "direct").unwrap()),
        );
        let runtime = crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
            generation: crate::dns::runtime::RuntimeGeneration::new(0),
            forwarder: Arc::clone(&forwarder),
            router: Arc::clone(&runtime_router),
            group_manager: Arc::new(GroupManager::new(&config.groups, &config.nodes)),
            policy_id: crate::dns::policy::PolicyId::from_config(&config.dns).unwrap_or_else(
                |_| {
                    crate::dns::policy::PolicyId::from_config(
                        &honk_config::dns::DnsConfig::default(),
                    )
                    .unwrap()
                },
            ),
            routing_projection: Arc::new(crate::dns::runtime::RoutingProjectionSnapshot::new(
                0,
                runtime_router,
                std::collections::HashMap::new(),
            )),
            cache: forwarder.cache(),
            persistence: crate::dns::runtime::ProcessPersistenceHandle::new(forwarder.cache()),
            transport: Arc::new(NoopRuntimeTransport),
        });
        Self::new_with_runtime(
            forwarder,
            Arc::new(crate::dns::runtime::DnsServiceProvider::new(runtime)),
            ebpf,
            router,
        )
    }

    pub(crate) fn new_with_runtime(
        forwarder: Arc<DnsForwarder>,
        runtime_provider: Arc<crate::dns::runtime::DnsServiceProvider>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        _router: Arc<RwLock<Router>>,
    ) -> Self {
        let snapshot = {
            let runtime = runtime_provider.acquire();
            Arc::clone(runtime.runtime().routing_projection())
        };
        let routing_projection =
            crate::dns::projection::RoutingProjection::spawn(Arc::clone(&ebpf), snapshot);
        Self {
            forwarder: Arc::new(RwLock::new((*forwarder).clone())),
            runtime_provider,
            routing_projection,
            concurrency_limit: Semaphore::new(DEFAULT_MAX_CONCURRENT_QUERIES),
        }
    }

    /// Resolve a domain (A + AAAA) through the *currently installed*
    /// forwarder — reload-safe, unlike holding a resolver from startup.
    /// Used by the health-check resolver hook.
    pub async fn resolve_domain(&self, domain: &str) -> Vec<std::net::IpAddr> {
        let runtime = self.runtime_provider.acquire();
        let mut out = Vec::new();
        for qtype in [1u16, 28] {
            let query = crate::dns::forwarder::build_dns_query(domain, qtype);
            if let Ok(resp) = runtime.runtime().resolve(&query).await {
                out.extend(crate::dns::forwarder::extract_answer_ips(&resp));
            }
        }
        out
    }

    /// Replace the DNS forwarder used by this controller (e.g. after config
    /// reload changed the upstream list or outbound routing).
    pub async fn set_forwarder(&self, forwarder: Arc<DnsForwarder>) {
        let mut guard = self.forwarder.write().await;
        *guard = (*forwarder).clone();
    }

    pub(crate) async fn prepare_forwarder_update(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, DnsForwarder> {
        self.forwarder.write().await
    }

    pub(crate) fn runtime_provider(&self) -> Arc<crate::dns::runtime::DnsServiceProvider> {
        Arc::clone(&self.runtime_provider)
    }

    pub(crate) fn update_projection_snapshot(
        &self,
        snapshot: Arc<crate::dns::projection::RoutingProjectionSnapshot>,
    ) {
        self.routing_projection.update_snapshot(snapshot);
    }

    /// Return a clone of the DNS cache so it can be reused across reloads.
    pub async fn cache(&self) -> Arc<tokio::sync::Mutex<crate::dns::cache::DnsCache>> {
        let runtime = self.runtime_provider.acquire();
        Arc::clone(runtime.runtime().cache())
    }

    /// Return a clone of the currently installed DNS forwarder (cheap: all
    /// fields are `Arc`s). Used by the clash API `/dns/query` endpoint so
    /// queries go through the same cache/routing/upstream pipeline as
    /// intercepted DNS traffic.
    pub async fn forwarder(&self) -> DnsForwarder {
        self.forwarder.read().await.clone()
    }

    /// Shared cell of the currently installed forwarder: callers holding
    /// this see reloads immediately (unlike a one-shot `forwarder()` clone).
    pub fn forwarder_cell(&self) -> Arc<RwLock<DnsForwarder>> {
        self.forwarder.clone()
    }

    /// Handle a UDP DNS query from TPROXY.
    pub async fn handle_udp_dns(
        &self,
        _udp_socket: &UdpSocket,
        data: &[u8],
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 {
            return Ok(false);
        }
        if !is_dns_query(data) {
            return Ok(false);
        }

        // Hold the permit until the response is written — acquiring and
        // immediately dropping it would make the concurrency limit a no-op.
        let _permit = match self.concurrency_limit.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                debug!("DNS concurrency limit reached; sending REFUSED");
                let servfail = build_dns_refused(data);
                let _ =
                    super::send_udp_reply_from_orig_dst(&servfail, client_addr, original_dst).await;
                return Ok(true);
            }
        };

        debug!(
            "DNS controller (UDP): forwarding query from {}",
            client_addr
        );

        let response = self
            .resolve_with_singleflight(data, Some(original_dst))
            .await;
        let _ = super::send_udp_reply_from_orig_dst(&response, client_addr, original_dst).await;
        Ok(true)
    }

    /// Handle a TCP DNS-over-TCP connection from TPROXY.
    pub async fn handle_tcp_dns(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 {
            return Ok(false);
        }

        use tokio::io::AsyncReadExt;

        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(false);
        }
        let mut length = u16::from_be_bytes(len_buf) as usize;
        if !(12..=65535).contains(&length) {
            return Ok(false);
        }

        let mut dns_data = vec![0u8; length];
        if stream.read_exact(&mut dns_data).await.is_err() {
            return Ok(false);
        }

        if !is_dns_query(&dns_data) {
            return Ok(false);
        }

        debug!(
            "DNS controller (TCP): forwarding query from {}",
            client_addr
        );

        match self.concurrency_limit.try_acquire() {
            Ok(_permit) => {
                let response = self
                    .resolve_with_singleflight(&dns_data, Some(original_dst))
                    .await;
                write_tcp_dns_response(stream, &response).await?;
            }
            Err(_) => {
                let response = build_dns_refused(&dns_data);
                write_tcp_dns_response(stream, &response).await?;
            }
        }

        loop {
            if stream.read_exact(&mut len_buf).await.is_err() {
                return Ok(true);
            }
            length = u16::from_be_bytes(len_buf) as usize;
            if !(12..=65535).contains(&length) {
                return Ok(true);
            }

            dns_data.resize(length, 0);
            if stream.read_exact(&mut dns_data).await.is_err() {
                return Ok(true);
            }

            if !is_dns_query(&dns_data) {
                return Ok(true);
            }

            // Same as the UDP path: the permit must stay alive until the
            // response is written.
            match self.concurrency_limit.try_acquire() {
                Ok(_permit) => {
                    let response = self
                        .resolve_with_singleflight(&dns_data, Some(original_dst))
                        .await;
                    write_tcp_dns_response(stream, &response).await?;
                }
                Err(_) => {
                    let response = build_dns_refused(&dns_data);
                    write_tcp_dns_response(stream, &response).await?;
                }
            }
        }
    }

    /// Resolve a DNS query with singleflight deduplication.
    async fn resolve_with_singleflight(
        &self,
        data: &[u8],
        original_dst: Option<SocketAddr>,
    ) -> Vec<u8> {
        self.resolve_and_notify(data, original_dst).await.0
    }

    /// Resolve a raw DNS query and notify BPF on success.
    async fn resolve_and_notify(
        &self,
        data: &[u8],
        original_dst: Option<SocketAddr>,
    ) -> (Vec<u8>, bool) {
        let runtime = self.runtime_provider.acquire();
        match runtime
            .runtime()
            .forwarder()
            .resolve_outcome_with_context(data, original_dst)
            .await
        {
            Ok(outcome) => {
                self.submit_projection(runtime.runtime(), data, &outcome);
                (outcome.rendered().to_vec(), true)
            }
            Err(e) => {
                debug!("DNS controller forward failed: {}; sending SERVFAIL", e);
                (build_dns_servfail(data), true)
            }
        }
    }

    fn submit_projection(
        &self,
        runtime: &crate::dns::runtime::DnsRuntime,
        query: &[u8],
        outcome: &crate::dns::outcome::DnsOutcome,
    ) {
        use crate::dns::outcome::{OutcomeStatus, Provenance, ResponseClass};
        use crate::dns::projection::{ProjectionFreshness, ProjectionObservation};

        let Some((domain, _)) = crate::dns::forwarder::parse_dns_question(query) else {
            return;
        };
        let positive_ips = (outcome.status() == OutcomeStatus::Accepted
            && outcome.response_class() == ResponseClass::Positive)
            .then(|| crate::dns::forwarder::extract_answer_ips(outcome.rendered()));
        let observation = match (outcome.status(), outcome.response_class()) {
            (OutcomeStatus::Accepted, ResponseClass::Positive) => ProjectionObservation::Positive {
                domain: &domain,
                ips: positive_ips.as_deref().unwrap_or_default(),
                advertised_ttl: outcome.expiry().ttl(),
                freshness: if outcome.provenance() == Provenance::Stale {
                    ProjectionFreshness::Stale
                } else {
                    ProjectionFreshness::Fresh
                },
            },
            (OutcomeStatus::Accepted, ResponseClass::Nodata | ResponseClass::Nxdomain) => {
                ProjectionObservation::Clear { domain: &domain }
            }
            (OutcomeStatus::Accepted, ResponseClass::Servfail) | (OutcomeStatus::Rejected, _) => {
                ProjectionObservation::Retain { domain: &domain }
            }
        };
        self.routing_projection
            .submit(Arc::clone(runtime.routing_projection()), observation);
    }
}

fn is_dns_query(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    if data[2] & 0x80 != 0 {
        return false;
    }
    crate::dns::forwarder::parse_dns_question(data).is_some()
}

fn build_dns_servfail(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 2)
}

/// REFUSED (rcode 5) for concurrency-limit degradation: tells the client to
/// back off instead of retrying into the storm (unlike SERVFAIL).
fn build_dns_refused(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 5)
}

/// Minimal error response: the query with QR/RA set and the given rcode.
/// Counts are left as-is (a query has no answers anyway).
pub(crate) fn build_dns_error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    if query.len() < 12 {
        return vec![0u8; 12];
    }
    let mut resp = query.to_vec();
    resp[2] = 0x81; // QR + RD
    resp[3] = 0x80 | (rcode & 0x0f); // RA + rcode
    resp
}

async fn write_tcp_dns_response(stream: &mut TcpStream, response: &[u8]) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let resp_len = (response.len() as u16).to_be_bytes();
    stream.write_all(&resp_len).await?;
    stream.write_all(response).await?;
    Ok(())
}

#[cfg(test)]
mod singleflight_tests {
    use super::*;
    use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
    use crate::routing::Router;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct SlowUpstream {
        calls: AtomicUsize,
        delay: Duration,
        response: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl DnsUpstreamPool for SlowUpstream {
        async fn query(&self, _name: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(self.response.clone())
        }
    }

    fn test_controller(
        response: Vec<u8>,
        delay: Duration,
    ) -> (Arc<DnsController>, Arc<SlowUpstream>) {
        let upstream = Arc::new(SlowUpstream {
            calls: AtomicUsize::new(0),
            delay,
            response,
        });
        let forwarder = Arc::new(DnsForwarder::new(
            upstream.clone(),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            Arc::new(
                crate::dns::routing::DnsRouter::new_from_dns_config(
                    &honk_config::dns::DnsConfig::default(),
                )
                .unwrap(),
            ),
        ));
        let controller = Arc::new(DnsController::new(
            forwarder,
            Arc::new(RwLock::new(Box::new(
                crate::ebpf::mock::MockEbpfBackend::new(),
            ))),
            Arc::new(RwLock::new(Router::new(&[], "direct").unwrap())),
        ));
        (controller, upstream)
    }

    fn controller_with_limit(
        upstream: Arc<dyn DnsUpstreamPool>,
        max_concurrent_queries: usize,
    ) -> Arc<DnsController> {
        let forwarder = Arc::new(DnsForwarder::new(
            upstream,
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            Arc::new(
                crate::dns::routing::DnsRouter::new_from_dns_config(
                    &honk_config::dns::DnsConfig::default(),
                )
                .unwrap(),
            ),
        ));
        let mut controller = DnsController::new(
            forwarder,
            Arc::new(RwLock::new(Box::new(
                crate::ebpf::mock::MockEbpfBackend::new(),
            ))),
            Arc::new(RwLock::new(Router::new(&[], "direct").unwrap())),
        );
        controller.concurrency_limit = Semaphore::new(max_concurrent_queries);
        Arc::new(controller)
    }

    fn query_with_txid(domain: &str, txid: u16) -> Vec<u8> {
        let mut q = crate::dns::forwarder::build_dns_query(domain, 1);
        q[0..2].copy_from_slice(&txid.to_be_bytes());
        q
    }

    fn response_with_txid(domain: &str, txid: u16) -> Vec<u8> {
        let mut resp = crate::dns::forwarder::build_dns_query(domain, 1);
        resp[0..2].copy_from_slice(&txid.to_be_bytes());
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp
    }

    fn multi_question_query(txid: u16) -> Vec<u8> {
        let mut query = query_with_txid("example.com", txid);
        let second = query_with_txid("other.example", txid);
        query[4..6].copy_from_slice(&2_u16.to_be_bytes());
        query.extend_from_slice(&second[12..]);
        query
    }

    /// Concurrent duplicate queries share one upstream flight, and each
    /// waiter gets the response with its OWN transaction id restored.
    #[tokio::test]
    async fn singleflight_dedups_and_restores_txid() {
        let (controller, upstream) = test_controller(
            response_with_txid("example.com", 0x1111),
            Duration::from_millis(100),
        );
        let q1 = query_with_txid("example.com", 0xaaaa);
        let q2 = query_with_txid("example.com", 0xbbbb);
        let (r1, r2) = tokio::join!(
            controller.resolve_with_singleflight(&q1, None),
            controller.resolve_with_singleflight(&q2, None),
        );
        assert_eq!(&r1[0..2], &q1[0..2], "waiter 1 keeps its own txid");
        assert_eq!(&r2[0..2], &q2[0..2], "waiter 2 keeps its own txid");
        assert_eq!(
            upstream.calls.load(Ordering::SeqCst),
            1,
            "deduped to one upstream query"
        );
    }

    #[tokio::test]
    async fn ineligible_queries_bypass_singleflight() {
        let (controller, upstream) = test_controller(
            response_with_txid("example.com", 0x1111),
            Duration::from_millis(100),
        );
        let first = multi_question_query(0xaaaa);
        let second = multi_question_query(0xbbbb);

        let _ = tokio::join!(
            controller.resolve_with_singleflight(&first, None),
            controller.resolve_with_singleflight(&second, None),
        );

        assert_eq!(
            upstream.calls.load(Ordering::SeqCst),
            2,
            "ineligible requests must not share an upstream flight"
        );
    }

    struct SnapshotUpstream {
        ip: [u8; 4],
        calls: AtomicUsize,
        entered: Option<Arc<Notify>>,
        release: Option<Arc<Notify>>,
    }

    #[async_trait::async_trait]
    impl DnsUpstreamPool for SnapshotUpstream {
        async fn query(&self, _name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0
                && let (Some(entered), Some(release)) = (&self.entered, &self.release)
            {
                entered.notify_one();
                release.notified().await;
            }
            Ok(a_response(raw, self.ip))
        }
    }

    fn a_response(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, ip[0], ip[1], ip[2], ip[3],
        ]);
        response
    }

    fn snapshot_forwarder(upstream: Arc<SnapshotUpstream>) -> Arc<DnsForwarder> {
        Arc::new(
            DnsForwarder::new(
                upstream,
                Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                    16,
                ))),
                Arc::new(
                    crate::dns::routing::DnsRouter::new_from_dns_config(
                        &honk_config::dns::DnsConfig::default(),
                    )
                    .expect("router"),
                ),
            )
            .with_cache_enabled(false),
        )
    }

    fn snapshot_controller(forwarder: Arc<DnsForwarder>) -> Arc<DnsController> {
        Arc::new(DnsController::new(
            forwarder,
            Arc::new(RwLock::new(Box::new(
                crate::ebpf::mock::MockEbpfBackend::new(),
            ))),
            Arc::new(RwLock::new(Router::new(&[], "direct").expect("router"))),
        ))
    }

    async fn publish_snapshot_forwarder(controller: &DnsController, forwarder: Arc<DnsForwarder>) {
        controller.set_forwarder(Arc::clone(&forwarder)).await;
        let current = controller.runtime_provider.acquire();
        let runtime = crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
            generation: crate::dns::runtime::RuntimeGeneration::new(
                current.runtime().generation().get().saturating_add(1),
            ),
            forwarder: Arc::clone(&forwarder),
            router: Arc::clone(current.runtime().router()),
            group_manager: Arc::clone(current.runtime().group_manager()),
            policy_id: current.runtime().policy_id().clone(),
            routing_projection: Arc::clone(current.runtime().routing_projection()),
            cache: forwarder.cache(),
            persistence: Arc::clone(current.runtime().persistence()),
            transport: Arc::new(NoopRuntimeTransport),
        });
        drop(current);
        controller.runtime_provider.publish(runtime);
    }

    #[tokio::test]
    async fn set_forwarder_does_not_wait_for_resolve_and_notify_exchange() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let old = snapshot_forwarder(Arc::new(SnapshotUpstream {
            ip: [192, 0, 2, 1],
            calls: AtomicUsize::new(0),
            entered: Some(entered.clone()),
            release: Some(release.clone()),
        }));
        let controller = snapshot_controller(old);
        let query = crate::dns::forwarder::build_dns_query("example.com", 1);
        let running = {
            let controller = controller.clone();
            let query = query.clone();
            tokio::spawn(async move { controller.resolve_and_notify(&query, None).await })
        };
        entered.notified().await;
        let new = snapshot_forwarder(Arc::new(SnapshotUpstream {
            ip: [198, 51, 100, 2],
            calls: AtomicUsize::new(0),
            entered: None,
            release: None,
        }));

        let publication = tokio::time::timeout(
            Duration::from_millis(100),
            publish_snapshot_forwarder(&controller, new),
        )
        .await;
        if publication.is_err() {
            release.notify_waiters();
            let _ = running.await;
            panic!("set_forwarder waited for the old upstream exchange");
        }
        assert!(!running.is_finished(), "old query must remain paused");
        release.notify_waiters();
        let (old_response, _) = running.await.expect("old query task");
        let (new_response, _) = controller.resolve_and_notify(&query, None).await;

        assert_eq!(
            crate::dns::forwarder::extract_answer_ips(&old_response),
            ["192.0.2.1".parse::<std::net::IpAddr>().expect("old IP")]
        );
        assert_eq!(
            crate::dns::forwarder::extract_answer_ips(&new_response),
            ["198.51.100.2".parse::<std::net::IpAddr>().expect("new IP")]
        );
    }

    #[tokio::test]
    async fn resolve_domain_keeps_old_snapshot_without_blocking_publication() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let old = snapshot_forwarder(Arc::new(SnapshotUpstream {
            ip: [192, 0, 2, 3],
            calls: AtomicUsize::new(0),
            entered: Some(entered.clone()),
            release: Some(release.clone()),
        }));
        let controller = snapshot_controller(old);
        let running = {
            let controller = controller.clone();
            tokio::spawn(async move { controller.resolve_domain("example.com").await })
        };
        entered.notified().await;
        let new = snapshot_forwarder(Arc::new(SnapshotUpstream {
            ip: [198, 51, 100, 4],
            calls: AtomicUsize::new(0),
            entered: None,
            release: None,
        }));

        let publication = tokio::time::timeout(
            Duration::from_millis(100),
            publish_snapshot_forwarder(&controller, new),
        )
        .await;
        if publication.is_err() {
            release.notify_waiters();
            let _ = running.await;
            panic!("set_forwarder waited for resolve_domain");
        }
        assert!(!running.is_finished(), "old lookup must remain paused");
        release.notify_waiters();
        let old_ips = running.await.expect("old lookup task");
        let new_ips = controller.resolve_domain("example.com").await;

        assert!(
            old_ips
                .iter()
                .all(|ip| { *ip == "192.0.2.3".parse::<std::net::IpAddr>().expect("old IP") })
        );
        assert!(
            new_ips
                .iter()
                .all(|ip| { *ip == "198.51.100.4".parse::<std::net::IpAddr>().expect("new IP") })
        );
    }

    struct BlockingFirstUpstream {
        first_entered: Notify,
        release_first: Notify,
    }

    #[async_trait::async_trait]
    impl DnsUpstreamPool for BlockingFirstUpstream {
        async fn query(&self, _name: &str, raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            let (domain, _) =
                crate::dns::forwarder::parse_dns_question(raw).expect("valid test query");
            if domain == "first.example" {
                self.first_entered.notify_one();
                self.release_first.notified().await;
            }
            Ok(response_with_txid(
                &domain,
                u16::from_be_bytes([raw[0], raw[1]]),
            ))
        }
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    async fn write_tcp_query(stream: &mut TcpStream, query: &[u8]) {
        use tokio::io::AsyncWriteExt;
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(query).await.unwrap();
    }

    async fn read_tcp_response(stream: &mut TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.unwrap();
        let mut response = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn first_tcp_frame_holds_permit_until_response_is_written() {
        let upstream = Arc::new(BlockingFirstUpstream {
            first_entered: Notify::new(),
            release_first: Notify::new(),
        });
        let controller = controller_with_limit(upstream.clone(), 1);
        let original_dst: SocketAddr = "127.0.0.1:53".parse().unwrap();

        let (mut first_client, mut first_server) = tcp_pair().await;
        let first_controller = controller.clone();
        let first_task = tokio::spawn(async move {
            first_controller
                .handle_tcp_dns(
                    &mut first_server,
                    "127.0.0.1:10001".parse().unwrap(),
                    original_dst,
                )
                .await
        });
        write_tcp_query(&mut first_client, &query_with_txid("first.example", 0x1111)).await;
        upstream.first_entered.notified().await;

        let (mut second_client, mut second_server) = tcp_pair().await;
        let second_controller = controller.clone();
        let second_task = tokio::spawn(async move {
            second_controller
                .handle_tcp_dns(
                    &mut second_server,
                    "127.0.0.1:10002".parse().unwrap(),
                    original_dst,
                )
                .await
        });
        write_tcp_query(
            &mut second_client,
            &query_with_txid("second.example", 0x2222),
        )
        .await;
        let second_response = read_tcp_response(&mut second_client).await;

        assert_eq!(
            second_response[3] & 0x0f,
            5,
            "a distinct first-frame query must be REFUSED while the sole permit is held"
        );

        upstream.release_first.notify_one();
        let first_response = read_tcp_response(&mut first_client).await;
        assert_eq!(first_response[3] & 0x0f, 0);
        drop(first_client);
        drop(second_client);
        first_task.await.unwrap().unwrap();
        second_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancelled_first_tcp_frame_releases_permit() {
        let upstream = Arc::new(BlockingFirstUpstream {
            first_entered: Notify::new(),
            release_first: Notify::new(),
        });
        let controller = controller_with_limit(upstream.clone(), 1);
        let original_dst: SocketAddr = "127.0.0.1:53".parse().unwrap();

        let (mut first_client, mut first_server) = tcp_pair().await;
        let first_controller = controller.clone();
        let first_task = tokio::spawn(async move {
            first_controller
                .handle_tcp_dns(
                    &mut first_server,
                    "127.0.0.1:10003".parse().unwrap(),
                    original_dst,
                )
                .await
        });
        write_tcp_query(&mut first_client, &query_with_txid("first.example", 0x3333)).await;
        upstream.first_entered.notified().await;
        first_task.abort();
        assert!(first_task.await.unwrap_err().is_cancelled());
        drop(first_client);

        let (mut resumed_client, mut resumed_server) = tcp_pair().await;
        let resumed_controller = controller.clone();
        let resumed_task = tokio::spawn(async move {
            resumed_controller
                .handle_tcp_dns(
                    &mut resumed_server,
                    "127.0.0.1:10004".parse().unwrap(),
                    original_dst,
                )
                .await
        });
        write_tcp_query(
            &mut resumed_client,
            &query_with_txid("resumed.example", 0x4444),
        )
        .await;
        let resumed_response = read_tcp_response(&mut resumed_client).await;
        assert_eq!(
            resumed_response[3] & 0x0f,
            0,
            "cancelling the permit owner must allow a new first-frame query"
        );
        drop(resumed_client);
        resumed_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_first_tcp_frame_is_not_handled() {
        use tokio::io::AsyncWriteExt;

        let (controller, _) =
            test_controller(response_with_txid("example.com", 0x5555), Duration::ZERO);
        let (mut client, mut server) = tcp_pair().await;
        let task = tokio::spawn(async move {
            controller
                .handle_tcp_dns(
                    &mut server,
                    "127.0.0.1:10005".parse().unwrap(),
                    "127.0.0.1:53".parse().unwrap(),
                )
                .await
        });
        client.write_all(&5u16.to_be_bytes()).await.unwrap();
        client.write_all(&[0u8; 5]).await.unwrap();

        assert!(!task.await.unwrap().unwrap());
    }
}
