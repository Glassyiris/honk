//! DNS forwarding engine that combines caching, routing, and upstream
//! querying into a single resolution pipeline.
//!
//! The forwarder accepts raw DNS wire-format queries, routes them to
//! the appropriate upstream based on domain matching, caches responses,
//! and returns the result.  It also supports background prefetch to
//! warm the cache for frequently-accessed domains.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::{Mutex, OnceCell};

use super::cache::{DnsCache, DnsCacheService};
use super::engine::EngineError;
use super::policy::PolicyId;
use super::response::ResponseError;
use super::routing::DnsRouter;
use honk_config::dns::{DnsConfig, DnsStrategy};

/// Abstraction over a pool of DNS upstream servers.
///
/// Implementations are expected to maintain connections to multiple
/// DNS upstreams and route raw queries to the named upstream.
#[async_trait]
pub trait DnsUpstreamPool: Send + Sync {
    /// Send a raw DNS query to the named upstream and return the
    /// raw wire-format response.
    async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>>;
}

#[derive(Debug, Error)]
pub enum DnsForwardError {
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error("DNS exchange with upstream '{upstream}' failed: {source}")]
    Exchange {
        upstream: String,
        #[source]
        source: anyhow::Error,
    },
    #[error(transparent)]
    Response(#[from] ResponseError),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    #[error("rejected DNS request escaped the request-plan branch")]
    RejectedPlanEscaped,
}

#[derive(Debug, Error)]
enum AsIsExchangeError {
    #[error("create asis UDP socket: {source}")]
    Socket {
        #[source]
        source: std::io::Error,
    },
    #[error("configure asis UDP socket as nonblocking: {source}")]
    Nonblocking {
        #[source]
        source: std::io::Error,
    },
    #[error("apply asis UDP bypass mark: {source}")]
    BypassMark {
        #[source]
        source: std::io::Error,
    },
    #[error("bind asis UDP socket: {source}")]
    Bind {
        #[source]
        source: std::io::Error,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum ResolveMode {
    Strict,
    Compatibility,
}

/// Notifier called when a domain is resolved (cache miss → upstream query).
///
/// The control plane implements this to update eBPF DOMAIN_ROUTING_MAP
/// proactively, so subsequent connections to the resolved IPs can be
/// routed by eBPF without userspace involvement.
pub trait DomainResolveNotifier: Send + Sync {
    /// Called after a successful upstream resolution with the domain name
    /// and the raw DNS response bytes.
    fn on_domain_resolved(&self, domain: &str, response: &[u8]);
}

/// DNS forwarder that resolves queries through a pipeline of
/// cache → routing → upstream → cache.
///
/// Optionally notifies a [`DomainResolveNotifier`] after successful
/// resolution so the control plane can proactively update eBPF
/// domain routing maps.
///
/// # Pipeline
///
/// ```text
/// raw_query
///   │
///   ├─ parse domain + qtype
///   ├─ strategy filter (empty A/AAAA)
///   ├─ request routing (reject / asis / upstream)  — before cache (dae order)
///   ├─ cache.get(key)  ── hit ──→ return cached bytes
///   │       │ miss
///   ├─ upstream_pool.query / asis dial
///   ├─ response routing loop (accept / reject / requery, depth ≤ 3)
///   ├─ fixed_domain_ttl / optimistic_cache_ttl
///   ├─ cache.put
///   ├─ notifier.on_domain_resolved
///   └─ return response
/// ```
#[derive(Clone)]
pub struct DnsForwarder {
    pub(crate) upstream_pool: Arc<dyn DnsUpstreamPool>,
    pub(crate) cache: Arc<Mutex<DnsCache>>,
    cache_service: Arc<OnceCell<Arc<DnsCacheService>>>,
    pub(crate) routing: Arc<DnsRouter>,
    pub(crate) strategy: DnsStrategy,
    /// When false, skip positive/negative cache lookups and inserts
    /// (`dns.optimistic_cache` / `cache.enabled`).
    pub(crate) cache_enabled: bool,
    /// Fixed positive-cache TTL in seconds (`dns.optimistic_cache_ttl` /
    /// `cache.ttl`). Overrides answer-section min TTL when storing entries
    /// and when rewriting wire TTLs on the way into the cache. `0` falls
    /// back to the answer min TTL (default path uses 600).
    pub(crate) cache_ttl: u32,
    pub(crate) notifier: Option<Arc<dyn DomainResolveNotifier>>,
    pub(crate) policy_id: Option<PolicyId>,
    prefetch_tasks: Arc<prefetch::PrefetchTasks>,
}

impl DnsForwarder {
    /// Create a new forwarder with the given upstream pool, cache, and router.
    pub fn new(
        upstream_pool: Arc<dyn DnsUpstreamPool>,
        cache: Arc<Mutex<DnsCache>>,
        routing: Arc<DnsRouter>,
    ) -> Self {
        Self {
            upstream_pool,
            cache,
            cache_service: Arc::new(OnceCell::new()),
            routing,
            strategy: DnsStrategy::default(),
            cache_enabled: true,
            // 0 = keep answer min TTL until `with_cache_ttl` is applied from config.
            cache_ttl: 0,
            notifier: None,
            policy_id: None,
            prefetch_tasks: prefetch::PrefetchTasks::new(),
        }
    }

    /// Create a new forwarder with a domain resolve notifier.
    pub fn with_notifier(
        upstream_pool: Arc<dyn DnsUpstreamPool>,
        cache: Arc<Mutex<DnsCache>>,
        routing: Arc<DnsRouter>,
        notifier: Arc<dyn DomainResolveNotifier>,
    ) -> Self {
        Self {
            upstream_pool,
            cache,
            cache_service: Arc::new(OnceCell::new()),
            routing,
            strategy: DnsStrategy::default(),
            cache_enabled: true,
            cache_ttl: 0,
            notifier: Some(notifier),
            policy_id: None,
            prefetch_tasks: prefetch::PrefetchTasks::new(),
        }
    }

    /// Set the IP-version strategy used for DNS responses.
    pub fn with_strategy(mut self, strategy: DnsStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Enable or disable the in-memory DNS cache (dae `optimistic_cache`).
    pub fn with_cache_enabled(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    /// Set the fixed positive-cache TTL (dae `optimistic_cache_ttl`).
    ///
    /// When non-zero, this value **overrides** the minimum TTL from the
    /// upstream answer for both cache lifetime and wire-format TTL fields
    /// stored in the cache. `0` keeps answer min TTL behaviour.
    pub fn with_cache_ttl(mut self, ttl_secs: u32) -> Self {
        self.cache_ttl = ttl_secs;
        self
    }

    pub fn with_policy_id(mut self, policy_id: PolicyId) -> Self {
        self.policy_id = Some(policy_id);
        self
    }

    pub fn with_policy_from_config(self, config: &DnsConfig) -> anyhow::Result<Self> {
        let policy_id =
            PolicyId::from_config(config).context("failed to derive DNS policy identity")?;
        Ok(self.with_policy_id(policy_id))
    }

    /// Return a clone of the underlying cache Arc.
    pub fn cache(&self) -> Arc<Mutex<DnsCache>> {
        self.cache.clone()
    }

    pub(crate) async fn cache_service(&self) -> Arc<DnsCacheService> {
        Arc::clone(
            self.cache_service
                .get_or_init(|| async { self.cache.lock().await.service() })
                .await,
        )
    }

    fn background_clone(&self) -> Self {
        Self {
            upstream_pool: Arc::clone(&self.upstream_pool),
            cache: Arc::clone(&self.cache),
            cache_service: Arc::clone(&self.cache_service),
            routing: Arc::clone(&self.routing),
            strategy: self.strategy.clone(),
            cache_enabled: self.cache_enabled,
            cache_ttl: self.cache_ttl,
            notifier: self.notifier.clone(),
            policy_id: self.policy_id.clone(),
            prefetch_tasks: prefetch::PrefetchTasks::closed(),
        }
    }

    pub(crate) async fn shutdown_prefetch(&self) {
        self.prefetch_tasks.shutdown().await;
    }
}

mod exchange;
mod message;
mod prefetch;
mod resolution;
mod response;
mod strategy;
mod ttl;

#[cfg(test)]
use message::new_asis_socket_with_mark;
pub use message::{build_dns_query, extract_answer_ips, parse_dns_question};
#[cfg(test)]
use response::dns_cache_key;
pub(crate) use response::{is_filtered_qtype, make_empty_response};
#[cfg(test)]
use ttl::effective_cache_ttl;
pub(crate) use ttl::{
    SERVE_STALE_TTL_SECS, extract_min_ttl, extract_soa_negative_ttl, rewrite_answer_ttls,
    traversal_strings,
};

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    use crate::dns::query::IngressProfile;

    include!("forwarder/tests/fixtures.rs");
    include!("forwarder/tests/service_flush.rs");
    include!("forwarder/tests/singleflight.rs");
    include!("forwarder/tests/stale_refresh.rs");
    include!("forwarder/tests/cache_routing.rs");
    include!("forwarder/tests/wire_helpers.rs");
    include!("forwarder/tests/rule_pipeline.rs");
    include!("forwarder/tests/requery_singleflight.rs");
    include!("forwarder/tests/context_and_family.rs");
    include!("forwarder/tests/family_and_negative.rs");
}
