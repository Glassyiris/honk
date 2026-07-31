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

#[cfg(test)]
use crate::dns::forwarder::DnsForwarder;
use crate::ebpf::EbpfBackend;
#[cfg(test)]
use crate::group::GroupManager;
#[cfg(test)]
use crate::routing::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tracing::debug;

mod transport;

#[cfg(test)]
mod tests;

pub(crate) use transport::build_dns_error_response;
use transport::build_dns_servfail;

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
    dns_service: crate::dns::DnsService,
    routing_projection: Arc<crate::dns::projection::RoutingProjection>,
    concurrency_limit: Semaphore,
}

impl DnsController {
    #[cfg(test)]
    pub fn new(
        forwarder: Arc<DnsForwarder>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        _router: Arc<RwLock<Router>>,
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
            outbound_runtime: None,
            transport: Arc::new(NoopRuntimeTransport),
        });
        Self::new_with_runtime(
            Arc::new(crate::dns::runtime::DnsServiceProvider::new(runtime)),
            ebpf,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_runtime(
        runtime_provider: Arc<crate::dns::runtime::DnsServiceProvider>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    ) -> Self {
        Self::new_with_service(
            crate::dns::DnsService::with_provider(runtime_provider),
            ebpf,
        )
    }

    pub(crate) fn new_with_service(
        dns_service: crate::dns::DnsService,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    ) -> Self {
        let snapshot = {
            let runtime = dns_service
                .provider()
                .unwrap_or_else(|| unreachable!("controller requires runtime DNS service"))
                .acquire();
            Arc::clone(runtime.runtime().routing_projection())
        };
        let routing_projection =
            crate::dns::projection::RoutingProjection::spawn(Arc::clone(&ebpf), snapshot);
        Self {
            dns_service,
            routing_projection,
            concurrency_limit: Semaphore::new(DEFAULT_MAX_CONCURRENT_QUERIES),
        }
    }

    /// Resolve a domain (A + AAAA) through the *currently installed*
    /// forwarder — reload-safe, unlike holding a resolver from startup.
    /// Used by the health-check resolver hook.
    pub async fn resolve_domain(&self, domain: &str) -> Vec<std::net::IpAddr> {
        match self.dns_service.resolve_name(domain).await {
            Ok(resolved) => resolved.ipv4.into_iter().chain(resolved.ipv6).collect(),
            Err(error) => {
                debug!(%error, "DNS controller name resolution failed");
                Vec::new()
            }
        }
    }

    pub(crate) fn runtime_provider(&self) -> Arc<crate::dns::runtime::DnsServiceProvider> {
        self.dns_service
            .provider()
            .unwrap_or_else(|| unreachable!("controller always uses runtime DNS service"))
    }

    pub(crate) fn dns_service(&self) -> crate::dns::DnsService {
        self.dns_service.clone()
    }

    pub(crate) async fn shutdown(&self) {
        self.routing_projection.shutdown().await;
        self.runtime_provider().shutdown().await;
    }

    pub(crate) fn update_projection_snapshot(
        &self,
        snapshot: Arc<crate::dns::projection::RoutingProjectionSnapshot>,
    ) {
        self.routing_projection.update_snapshot(snapshot);
    }

    pub async fn cache(&self) -> Arc<tokio::sync::Mutex<crate::dns::cache::DnsCache>> {
        self.dns_service.cache()
    }

    /// Resolve a DNS query with singleflight deduplication.
    async fn resolve_with_singleflight(
        &self,
        data: &[u8],
        original_dst: Option<SocketAddr>,
        ingress: crate::dns::query::IngressProfile,
    ) -> Vec<u8> {
        self.resolve_and_notify(data, original_dst, ingress).await.0
    }

    /// Resolve a raw DNS query and notify BPF on success.
    async fn resolve_and_notify(
        &self,
        data: &[u8],
        original_dst: Option<SocketAddr>,
        ingress: crate::dns::query::IngressProfile,
    ) -> (Vec<u8>, bool) {
        match self
            .dns_service
            .resolve_outcome_with_runtime(data, original_dst, ingress)
            .await
        {
            Ok((outcome, runtime)) => {
                self.submit_projection(runtime.runtime(), data, &outcome);
                let resp = outcome.rendered().to_vec();
                (resp, true)
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
