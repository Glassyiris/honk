//! DNS forwarding engine that combines caching, routing, and upstream
//! querying into a single resolution pipeline.
//!
//! The forwarder accepts raw DNS wire-format queries, routes them to
//! the appropriate upstream based on domain matching, caches responses,
//! and returns the result.  It also supports background prefetch to
//! warm the cache for frequently-accessed domains.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::{Mutex, OnceCell};
use tracing::{debug, trace};

use super::cache::{DnsCache, DnsCacheService, PublicationEpoch};
use super::engine::{DnsEngine, EngineError, PreparedQuery};
use super::outcome::{DnsOutcome, EffectiveExpiry, OutcomeParts, OutcomeStatus, Provenance};
use super::planner::{RequestScope, ResponseTraversal};
use super::policy::PolicyId;
use super::query::IngressProfile;
use super::response::{ResponseError, ResponseTemplate};
use super::routing::DnsRouter;
use super::wire::skip_dns_name;
use honk_config::dns::{DnsConfig, DnsStrategy};
use honk_ebpf_common::DAE_BYPASS_MARK;

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

    /// Resolve a raw DNS query (no original destination for `asis`).
    pub async fn resolve(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.resolve_with_profile(raw_query, IngressProfile::Internal)
            .await
    }

    /// Resolve a raw DNS query using an explicit caller ingress profile.
    pub async fn resolve_with_profile(
        &self,
        raw_query: &[u8],
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .resolve_inner(raw_query, None, ingress, false, ResolveMode::Compatibility)
            .await?
            .rendered()
            .to_vec())
    }

    /// Resolve a raw DNS query with optional original destination.
    ///
    /// `original_dst` is used when request routing selects `asis` (dial the
    /// intercepted packet's real DNS server). When `None`, `asis` falls back
    /// to the configured default upstream with a debug log.
    pub async fn resolve_with_context(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
    ) -> anyhow::Result<Vec<u8>> {
        self.resolve_with_context_and_profile(raw_query, original_dst, IngressProfile::Internal)
            .await
    }

    /// Resolve with an original destination and explicit caller ingress profile.
    pub async fn resolve_with_context_and_profile(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .resolve_inner(
                raw_query,
                original_dst,
                ingress,
                false,
                ResolveMode::Compatibility,
            )
            .await?
            .rendered()
            .to_vec())
    }

    pub async fn resolve_outcome(&self, raw_query: &[u8]) -> Result<DnsOutcome, DnsForwardError> {
        self.resolve_outcome_with_context(raw_query, None).await
    }

    pub async fn resolve_outcome_with_context(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
    ) -> Result<DnsOutcome, DnsForwardError> {
        self.resolve_outcome_with_context_and_profile(
            raw_query,
            original_dst,
            IngressProfile::Internal,
        )
        .await
    }

    pub async fn resolve_outcome_with_context_and_profile(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
        ingress: IngressProfile,
    ) -> Result<DnsOutcome, DnsForwardError> {
        self.resolve_inner(raw_query, original_dst, ingress, false, ResolveMode::Strict)
            .await
    }

    /// `bypass_cache_read` skips the cache/negative lookup — used by the
    /// stale-while-revalidate refresh so it always reaches the upstream
    /// (its result is still written back through the normal pipeline).
    async fn resolve_inner(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
        ingress: IngressProfile,
        bypass_cache_read: bool,
        mode: ResolveMode,
    ) -> Result<DnsOutcome, DnsForwardError> {
        let publication_epoch = self.cache_service().await.publication_epoch();
        let result = super::engine::pipeline::resolve(
            self,
            raw_query,
            original_dst,
            ingress,
            bypass_cache_read,
            mode,
            publication_epoch,
        )
        .await;
        match &result {
            Ok(outcome) => {
                let event = match (outcome.status(), outcome.response_class()) {
                    (super::outcome::OutcomeStatus::Rejected, _) => {
                        crate::stats::DnsStatEvent::OutcomeRejected
                    }
                    (
                        super::outcome::OutcomeStatus::Accepted,
                        super::outcome::ResponseClass::Positive,
                    ) => crate::stats::DnsStatEvent::OutcomePositive,
                    (
                        super::outcome::OutcomeStatus::Accepted,
                        super::outcome::ResponseClass::Nodata,
                    ) => crate::stats::DnsStatEvent::OutcomeNodata,
                    (
                        super::outcome::OutcomeStatus::Accepted,
                        super::outcome::ResponseClass::Nxdomain,
                    ) => crate::stats::DnsStatEvent::OutcomeNxdomain,
                    (
                        super::outcome::OutcomeStatus::Accepted,
                        super::outcome::ResponseClass::Servfail,
                    ) => crate::stats::DnsStatEvent::OutcomeServfail,
                };
                crate::stats::record_dns_event(event);
                tracing::debug!(
                    status = ?outcome.status(),
                    class = ?outcome.response_class(),
                    provenance = ?outcome.provenance(),
                    "DNS resolution outcome"
                );
            }
            Err(error) => {
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::OutcomeError);
                let error_kind = match error {
                    DnsForwardError::Engine(_) => "engine",
                    DnsForwardError::Exchange { .. } => "exchange",
                    DnsForwardError::Response(_) => "response",
                    DnsForwardError::Internal(_) => "internal",
                    DnsForwardError::RejectedPlanEscaped => "rejected_plan",
                };
                tracing::debug!(error_kind, "DNS resolution failed");
            }
        }
        result
    }

    pub(crate) async fn exchange(
        &self,
        scope: &RequestScope,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        match scope {
            RequestScope::Upstream(upstream) => {
                self.upstream_pool.query(upstream.as_str(), raw_query).await
            }
            RequestScope::AsIs(destination) => self.query_asis(raw_query, Some(*destination)).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn outcome_from_wire(
        &self,
        engine: &DnsEngine,
        prepared: &PreparedQuery,
        reusable: Vec<u8>,
        status: OutcomeStatus,
        provenance: Provenance,
        expiry: EffectiveExpiry,
        logical_upstream: Option<String>,
        final_upstream: Option<String>,
        requery_history: Vec<String>,
        mode: ResolveMode,
    ) -> Result<DnsOutcome, DnsForwardError> {
        let template = match ResponseTemplate::validate(prepared.query(), &reusable) {
            Ok(template) => Some(template),
            Err(_) if matches!(mode, ResolveMode::Compatibility) => None,
            Err(error) => return Err(error.into()),
        };
        let rendered = match &template {
            Some(template) => template.render(prepared.query())?,
            None => patch_txid(reusable.clone(), prepared.query().txid().get()),
        };
        Ok(DnsOutcome::new(OutcomeParts {
            status,
            response_class: super::engine::classify_response(&reusable),
            provenance,
            expiry,
            logical_upstream,
            final_upstream,
            requery_history,
            reusable,
            rendered,
            template,
            policy_id: engine.policy_id().cloned(),
        }))
    }

    /// RFC 8767 serve-stale: fall back to a recently-expired cache entry
    /// when the upstream phase fails. TTLs are rewritten to
    /// [`SERVE_STALE_TTL_SECS`] so the client re-asks soon, and the txid is
    /// patched to the caller's query.
    pub(crate) async fn try_serve_stale(
        &self,
        cache_key: &str,
        raw_query: &[u8],
        domain: &str,
    ) -> Option<Vec<u8>> {
        if !self.cache_enabled {
            return None;
        }
        let cache = self.cache_service().await;
        let entry = cache.get_stale(cache_key)?;
        let mut response = entry.response.clone();
        rewrite_answer_ttls(&mut response, SERVE_STALE_TTL_SECS);
        if response.len() >= 2 && raw_query.len() >= 2 {
            response[0..2].copy_from_slice(&raw_query[0..2]);
        }
        debug!(
            "DNS forwarder: serving stale cache for {} (upstream failure)",
            domain
        );
        Some(response)
    }

    /// Spawn a deduplicated background refresh for a hot entry nearing
    /// expiry (stale-while-revalidate). The refresh bypasses the cache read
    /// so it always reaches the upstream; the normal pipeline writes the
    /// fresh answer back.
    pub(crate) fn maybe_spawn_refresh(
        &self,
        cache: Arc<DnsCacheService>,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
        flight_key: crate::dns::cache::CacheKey,
        publication_epoch: PublicationEpoch,
    ) {
        let ingress = flight_key.ingress();
        let crate::dns::singleflight::FlightRole::Leader(owner) =
            cache.singleflight().acquire(flight_key)
        else {
            return;
        };
        let this = self.clone();
        let query = raw_query.to_vec();
        let spawned = cache.spawn_refresh(async move {
            let result = super::engine::pipeline::resolve_with_owner(
                &this,
                &query,
                original_dst,
                ingress,
                true,
                ResolveMode::Compatibility,
                super::engine::pipeline::ResolveExecution::refresh(owner, publication_epoch),
            )
            .await;
            if let Err(error) = result {
                debug!("DNS forwarder: background refresh failed: {error:#}");
            }
        });
        if !spawned {
            debug!("DNS forwarder: refresh service is closed");
        }
    }

    /// Prefer-mode strategy (sing-box / dae `ipversion_prefer` semantics):
    /// when the preferred family has answers for the same name, suppress the
    /// non-preferred family's response with NODATA; otherwise return it
    /// unchanged. Only-modes are handled earlier at request time.
    pub(crate) async fn apply_prefer_strategy(
        &self,
        raw_query: &[u8],
        domain: &str,
        qtype: u16,
        response: Vec<u8>,
        original_dst: Option<SocketAddr>,
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        let preferred = match (&self.strategy, qtype) {
            (DnsStrategy::PreferIpv4, 28) => 1u16,
            (DnsStrategy::PreferIpv6, 1) => 28u16,
            _ => return Ok(response),
        };
        if self
            .preferred_family_has_answers(domain, preferred, original_dst, ingress)
            .await
        {
            debug!(
                "DNS forwarder: suppressing {} answer for {} — preferred {} answers exist",
                qtype_name(qtype),
                domain,
                qtype_name(preferred)
            );
            return Ok(make_empty_response(raw_query, domain, qtype));
        }
        Ok(response)
    }

    /// Whether the preferred address family has answers for `domain`, checking
    /// the cache first and issuing a sibling query through the normal pipeline
    /// on a miss (its result is cached by that pipeline). The sibling query
    /// uses the preferred qtype, so `apply_prefer_strategy` never recurses.
    async fn preferred_family_has_answers(
        &self,
        domain: &str,
        preferred_qtype: u16,
        original_dst: Option<SocketAddr>,
        ingress: IngressProfile,
    ) -> bool {
        let sibling_key = dns_cache_key(domain, preferred_qtype);
        if self.cache_enabled {
            let cache = self.cache_service().await;
            if cache.negative_rcode(&sibling_key).is_some() {
                return false;
            }
            if let Some(entry) = cache.get(&sibling_key) {
                return response_has_family_ips(&entry.response, preferred_qtype);
            }
        }
        let query = build_dns_query(domain, preferred_qtype);
        // Boxed: breaks the async recursion cycle through resolve_with_context
        // (the sibling uses the preferred qtype, so it never re-enters here).
        let sibling =
            Box::pin(self.resolve_with_context_and_profile(&query, original_dst, ingress)).await;
        match sibling {
            Ok(resp) => response_has_family_ips(&resp, preferred_qtype),
            Err(e) => {
                debug!(
                    "DNS forwarder: preferred-family probe for {} failed: {}",
                    domain, e
                );
                false
            }
        }
    }

    /// Dial the original destination DNS server (dae `asis`).
    async fn query_asis(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
    ) -> anyhow::Result<Vec<u8>> {
        let Some(dst) = original_dst else {
            debug!("DNS forwarder: asis without original_dst — falling back to default upstream");
            return self.upstream_pool.query("default", raw_query).await;
        };

        debug!("DNS forwarder: asis dial {}", dst);
        let sock2 = new_asis_socket_with_mark(dst, |socket| {
            #[cfg(target_os = "linux")]
            {
                honk_outbound::util::set_mark_best_effort(socket, DAE_BYPASS_MARK)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = socket;
                Ok(())
            }
        })?;
        let socket = tokio::net::UdpSocket::from_std(sock2.into()).context("asis from_std")?;
        socket.connect(dst).await.context("asis connect")?;

        let resp = tokio::time::timeout(Duration::from_secs(5), async {
            socket.send(raw_query).await?;
            let mut buf = vec![0u8; 4096];
            let n = socket.recv(&mut buf).await?;
            buf.truncate(n);
            Ok::<_, std::io::Error>(buf)
        })
        .await
        .context("asis recv timeout")?
        .context("asis recv")?;
        Ok(resp)
    }

    /// Prefetch domains asynchronously to warm the cache.
    ///
    /// Constructs A-record queries for each domain and resolves them
    /// in background tasks.  Failures are silently ignored — the goal
    /// is best-effort cache warming.
    pub fn prefetch(&self, domains: &[String]) {
        for domain in domains {
            let domain = domain.clone();
            let query = build_dns_query(&domain, 1);
            let forwarder = self.clone();
            tokio::spawn(async move {
                match forwarder
                    .resolve_with_profile(&query, IngressProfile::Internal)
                    .await
                {
                    Err(e) => {
                        debug!("DNS prefetch: {} failed: {:#}", domain, e);
                    }
                    _ => {
                        trace!("DNS prefetch: {} cached successfully", domain);
                    }
                }
            });
        }
    }
}

fn new_asis_socket_with_mark(
    destination: SocketAddr,
    mark: impl FnOnce(&socket2::Socket) -> std::io::Result<()>,
) -> Result<socket2::Socket, AsIsExchangeError> {
    let domain = if destination.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)
        .map_err(|source| AsIsExchangeError::Socket { source })?;
    socket
        .set_nonblocking(true)
        .map_err(|source| AsIsExchangeError::Nonblocking { source })?;
    mark(&socket).map_err(|source| AsIsExchangeError::BypassMark { source })?;
    let bind_address = SocketAddr::new(
        if destination.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    socket
        .bind(&bind_address.into())
        .map_err(|source| AsIsExchangeError::Bind { source })?;
    Ok(socket)
}

/// Build a minimal DNS query for the given domain and query type.
pub fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let qname = encode_dns_name(domain);
    let mut query = Vec::with_capacity(12 + qname.len() + 4);

    // Header: ID=0, flags=0x0100 (RD), QDCOUNT=1, rest=0
    query.extend_from_slice(&[0x00, 0x00]); // ID
    query.extend_from_slice(&[0x01, 0x00]); // Flags (recursion desired)
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    query.extend_from_slice(&qname);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    query
}

/// Encode a domain name into DNS label format.
///
/// Example: `"example.com"` → `[0x07, b'e', ..., 0x03, b'c', b'o', b'm', 0x00]`
fn encode_dns_name(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in domain.split('.') {
        if label.len() > 63 {
            continue; // skip invalid labels
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0x00); // terminator
    encoded
}

/// Parse the first question from a raw DNS query.
///
/// Returns the domain name and QTYPE on success, or `None` if the
/// message is truncated or malformed.
pub fn parse_dns_question(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 16 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12; // skip 12-byte header
    let domain = decode_dns_name(data, &mut pos)?;

    if pos + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);

    Some((domain, qtype))
}

/// Decode a DNS name starting at `pos`, advancing `pos` past the name.
fn decode_dns_name(data: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut jump_pos = *pos;
    let mut max_jumps = 10; // prevent pointer loops

    loop {
        if jump_pos >= data.len() {
            return None;
        }
        let len = data[jump_pos];

        // Compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            if jump_pos + 2 > data.len() || max_jumps == 0 {
                return None;
            }
            max_jumps -= 1;
            let offset = ((len as usize & 0x3F) << 8) | (data[jump_pos + 1] as usize);
            if !jumped {
                *pos = jump_pos + 2; // advance past the pointer bytes
            }
            jump_pos = offset;
            jumped = true;
            continue;
        }

        if len == 0 {
            if !jumped {
                *pos = jump_pos + 1;
            }
            break;
        }

        if len > 63 {
            return None; // malformed label length
        }

        jump_pos += 1;
        if jump_pos + len as usize > data.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&data[jump_pos..jump_pos + len as usize])
                .ok()?
                .to_ascii_lowercase(),
        );
        jump_pos += len as usize;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Resolve the TTL used for positive cache inserts.
///
/// `configured` is `dns.cache.ttl` / `optimistic_cache_ttl`. Non-zero values
/// win (fixed override); `0` keeps the answer-section minimum.
/// Extract A/AAAA answer IPs from a wire-format DNS response.
pub fn extract_answer_ips(data: &[u8]) -> Vec<IpAddr> {
    super::wire::extract_ips_from_dns_response(data)
}

#[cfg(test)]
fn effective_cache_ttl(configured: u32, answer_min_ttl: u32) -> u32 {
    if configured > 0 {
        configured
    } else {
        answer_min_ttl.max(1)
    }
}

/// TTL advertised on answers served from the serve-stale fallback: small
/// enough that clients retry soon and pick up the recovery.
pub(crate) const SERVE_STALE_TTL_SECS: u32 = 30;

pub(crate) fn traversal_strings(traversal: &ResponseTraversal) -> Vec<String> {
    traversal
        .path()
        .iter()
        .map(|upstream| upstream.as_str().to_owned())
        .collect()
}

fn patch_txid(mut response: Vec<u8>, txid: u16) -> Vec<u8> {
    if let Some(bytes) = response.get_mut(0..2) {
        bytes.copy_from_slice(&txid.to_be_bytes());
    }
    response
}

/// RFC 2308 §5 negative-cache TTL: `min(SOA TTL, SOA MINIMUM)` from the
/// authority section, falling back to `default_ttl` when no SOA record is
/// present (or the message is malformed).
pub(crate) fn extract_soa_negative_ttl(data: &[u8], default_ttl: u32) -> u32 {
    if data.len() < 12 {
        return default_ttl;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return default_ttl;
        }
        pos += 4;
        if pos > data.len() {
            return default_ttl;
        }
    }
    // Skip answers; scan authority records for SOA (TYPE 6).
    for i in 0..(ancount + nscount) {
        if !skip_dns_name(data, &mut pos) {
            return default_ttl;
        }
        if pos + 10 > data.len() {
            return default_ttl;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        if i >= ancount && rtype == 6 && rdlength >= 20 && pos + 10 + rdlength <= data.len() {
            // SOA RDATA: MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE,
            // MINIMUM — the last u32 of RDATA.
            let minimum = u32::from_be_bytes([
                data[pos + 10 + rdlength - 4],
                data[pos + 10 + rdlength - 3],
                data[pos + 10 + rdlength - 2],
                data[pos + 10 + rdlength - 1],
            ]);
            return ttl.min(minimum).max(1);
        }
        pos += 10 + rdlength;
    }
    default_ttl
}

/// Overwrite TTL fields on every answer/authority/additional RR with `ttl`.
///
/// Used so cached (and client-visible) records reflect `optimistic_cache_ttl`
/// rather than the upstream's original values. Malformed tails are left as-is.
pub(crate) fn rewrite_answer_ttls(data: &mut [u8], ttl: u32) {
    if data.len() < 12 {
        return;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return;
        }
        pos += 4;
        if pos > data.len() {
            return;
        }
    }

    let ttl_be = ttl.to_be_bytes();
    for _ in 0..(ancount + nscount + arcount) {
        if !skip_dns_name(data, &mut pos) {
            return;
        }
        if pos + 10 > data.len() {
            return;
        }
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA
        data[pos + 4] = ttl_be[0];
        data[pos + 5] = ttl_be[1];
        data[pos + 6] = ttl_be[2];
        data[pos + 7] = ttl_be[3];
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }
}

/// Extract the minimum positive TTL from all answer/authority/additional
/// records in a DNS response.  Returns 60 if no TTL is found.
pub(crate) fn extract_min_ttl(data: &[u8]) -> u32 {
    if data.len() < 12 {
        return 60;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return 60;
        }
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() {
            return 60;
        }
    }

    let total_records = ancount + nscount + arcount;
    let mut min_ttl = u32::MAX;

    for _ in 0..total_records {
        if pos + 12 > data.len() {
            break;
        }
        if !skip_dns_name(data, &mut pos) {
            break;
        }
        if pos + 10 > data.len() {
            break;
        }

        // Record layout after NAME: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA(n)
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        if ttl > 0 && ttl < min_ttl {
            min_ttl = ttl;
        }

        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }

    if min_ttl == u32::MAX { 60 } else { min_ttl }
}

/// Build the cache key for a domain and query type.
pub(crate) fn dns_cache_key(domain: &str, qtype: u16) -> String {
    format!("{}:{}", domain, qtype)
}

/// Return `true` if the given query type is hard-filtered at request time.
/// Only the `*_only` strategies filter here; prefer strategies forward both
/// families and suppress at response time instead.
pub(crate) fn is_filtered_qtype(qtype: u16, strategy: &DnsStrategy) -> bool {
    match strategy {
        DnsStrategy::Ipv4Only => qtype == 28, // AAAA
        DnsStrategy::Ipv6Only => qtype == 1,  // A
        DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 | DnsStrategy::Both => false,
    }
}

/// Whether a wire-format response contains at least one address record of
/// the given family (qtype 1 = A, 28 = AAAA).
fn response_has_family_ips(response: &[u8], qtype: u16) -> bool {
    extract_answer_ips(response).iter().any(|ip| match qtype {
        1 => ip.is_ipv4(),
        28 => ip.is_ipv6(),
        _ => false,
    })
}

/// Human-readable qtype name for logging.
pub(crate) fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        2 => "NS",
        _ => "OTHER",
    }
}

/// Build a NODATA response (NOERROR, zero answers) for a filtered query,
/// preserving the query's transaction ID and question section.
pub(crate) fn make_empty_response(query: &[u8], domain: &str, qtype: u16) -> Vec<u8> {
    let mut resp = Vec::with_capacity(256);
    // Transaction ID (first two bytes of the query).
    resp.extend_from_slice(&query[0..2.min(query.len())]);
    if query.len() >= 3 {
        // Set QR=1, preserve RD; keep OPCODE/AA/TC bits from the query.
        resp.push((query[2] & 0x7F) | 0x80);
    } else {
        resp.push(0x80);
    }
    // RA=1, RCODE=0.
    resp.push(0x80);
    // QDCOUNT = 1.
    resp.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT, NSCOUNT, ARCOUNT = 0.
    resp.extend_from_slice(&[0u8; 6]);
    // Question section: encode domain labels.
    for label in domain.split('.') {
        resp.push(label.len() as u8);
        resp.extend_from_slice(label.as_bytes());
    }
    resp.push(0); // root label
    resp.extend_from_slice(&qtype.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    resp
}

#[cfg(test)]
mod tests {
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
            // Question: example.com A IN
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
            // Answer
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

    struct RefreshFenceUpstream {
        initial: Vec<u8>,
        refreshed: Vec<u8>,
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
            Ok(if call == 0 {
                self.initial.clone()
            } else {
                self.refreshed.clone()
            })
        }
    }

    #[tokio::test]
    async fn explicit_ingress_profiles_do_not_share_cache_entries() {
        let upstream = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 300)));
        let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), test_router());
        let query = make_a_query();

        forwarder
            .resolve_with_profile(&query, IngressProfile::Internal)
            .await
            .expect("internal response");
        forwarder
            .resolve_with_profile(&query, IngressProfile::Api)
            .await
            .expect("API response");

        assert_eq!(upstream.call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn service_flush_cancels_stalled_query_without_cache_resurrection() {
        let upstream = Arc::new(GatedUpstream {
            response: make_a_response([192, 0, 2, 1], 300),
            call_count: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let cache = test_cache();
        let service = crate::dns::DnsService::with_forwarder(Arc::new(DnsForwarder::new(
            upstream.clone(),
            cache.clone(),
            test_router(),
        )));
        let query = make_a_query();
        let resolving = {
            let service = service.clone();
            tokio::spawn(async move { service.resolve(&query, IngressProfile::Internal).await })
        };
        upstream.entered.notified().await;
        let persisted =
            tokio::time::timeout(std::time::Duration::from_secs(1), service.flush_cache())
                .await
                .expect("flush must complete while the query remains stalled")
                .expect("flush");
        assert!(!persisted);

        upstream.release.notify_waiters();
        let result = resolving.await.expect("resolve task");
        assert!(result.is_err(), "pre-flush query must be cancelled");
        assert!(cache.lock().await.is_empty());
    }

    #[tokio::test]
    async fn service_flush_fences_detached_refresh_memory_and_persistence() {
        use honk_config::experimental::CacheFileConfig;

        let directory = tempfile::tempdir().expect("tempdir");
        let database = Arc::new(
            crate::cachedb::CacheDb::open(
                &CacheFileConfig {
                    enabled: true,
                    path: directory
                        .path()
                        .join("cache.db")
                        .to_string_lossy()
                        .into_owned(),
                    cache_id: String::new(),
                    store_fakeip: false,
                    store_dns: true,
                },
                None,
            )
            .expect("cache.db"),
        );
        let persister = crate::dns::persist::DnsCachePersister::spawn(Arc::clone(&database));
        let upstream = Arc::new(RefreshFenceUpstream {
            initial: make_a_response([192, 0, 2, 1], 1),
            refreshed: make_a_response([192, 0, 2, 2], 300),
            call_count: AtomicUsize::new(0),
            refresh_entered: tokio::sync::Notify::new(),
            refresh_release: tokio::sync::Semaphore::new(0),
        });
        let cache = test_cache();
        cache.lock().await.set_persister(Some(persister.clone()));
        let service = crate::dns::DnsService::with_forwarder(Arc::new(DnsForwarder::new(
            upstream.clone(),
            cache.clone(),
            test_router(),
        )));
        let query = make_a_query();

        let primed = service
            .resolve(&query, IngressProfile::Internal)
            .await
            .expect("prime");
        assert!(primed.windows(4).any(|bytes| bytes == [192, 0, 2, 1]));
        let cached = service
            .resolve(&query, IngressProfile::Internal)
            .await
            .expect("near-expiry cache hit");
        assert!(cached.windows(4).any(|bytes| bytes == [192, 0, 2, 1]));
        tokio::time::timeout(Duration::from_secs(1), upstream.refresh_entered.notified())
            .await
            .expect("detached refresh entered");

        let persisted = tokio::time::timeout(Duration::from_secs(1), service.flush_cache())
            .await
            .expect("flush must acknowledge while refresh remains stalled")
            .expect("flush");
        assert!(persisted);
        upstream.refresh_release.add_permits(1);
        let cache_service = cache.lock().await.service();
        tokio::time::timeout(Duration::from_secs(1), async {
            while cache_service.refresh_task_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("old refresh completes");

        assert!(cache.lock().await.is_empty());
        persister.shutdown().await.expect("persistence shutdown");
        assert!(database.load_dns_v2().expect("persisted rows").is_empty());

        let refreshed = service
            .resolve(&query, IngressProfile::Internal)
            .await
            .expect("new-epoch query");
        assert!(refreshed.windows(4).any(|bytes| bytes == [192, 0, 2, 2]));
        assert_eq!(cache.lock().await.len(), 1);
        assert_eq!(upstream.call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn cancelled_persistent_flush_reopens_cache_publication() {
        use honk_config::experimental::CacheFileConfig;

        let directory = tempfile::tempdir().expect("tempdir");
        let database = Arc::new(
            crate::cachedb::CacheDb::open(
                &CacheFileConfig {
                    enabled: true,
                    path: directory
                        .path()
                        .join("cache.db")
                        .to_string_lossy()
                        .into_owned(),
                    cache_id: String::new(),
                    store_fakeip: false,
                    store_dns: true,
                },
                None,
            )
            .expect("cache.db"),
        );
        let persister = crate::dns::persist::DnsCachePersister::spawn(Arc::clone(&database));
        let cache = test_cache();
        cache.lock().await.set_persister(Some(persister.clone()));
        let service = crate::dns::DnsService::with_forwarder(Arc::new(DnsForwarder::new(
            Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 9], 300))),
            cache.clone(),
            test_router(),
        )));
        let (flush_entered, _flush_release) = persister.gate_next_flush();
        let flushing = {
            let service = service.clone();
            tokio::spawn(async move { service.flush_cache().await })
        };
        tokio::time::timeout(Duration::from_secs(1), flush_entered.notified())
            .await
            .expect("flush reached persistence acknowledgement wait");
        flushing.abort();
        assert!(
            flushing
                .await
                .expect_err("flush task cancelled")
                .is_cancelled(),
            "flush must be cancelled while persistence acknowledgement is gated"
        );

        service
            .resolve(&make_a_query(), IngressProfile::Internal)
            .await
            .expect("post-cancellation resolve");
        assert_eq!(cache.lock().await.len(), 1);
        persister.shutdown().await.expect("persistence shutdown");
        assert_eq!(database.load_dns_v2().expect("persisted rows").len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn identical_concurrent_queries_share_one_exchange_and_render_each_txid() {
        // Given
        const CALLERS: usize = 128;
        let upstream = Arc::new(GatedUpstream {
            response: make_a_response([192, 0, 2, 1], 300),
            call_count: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let cache = test_cache();
        let forwarder = Arc::new(DnsForwarder::new(
            upstream.clone(),
            cache.clone(),
            test_router(),
        ));
        let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
        let mut tasks = tokio::task::JoinSet::new();
        for txid in 1..=CALLERS {
            let forwarder = Arc::clone(&forwarder);
            let start = Arc::clone(&start);
            tasks.spawn(async move {
                let mut query = make_a_query();
                query[0..2].copy_from_slice(
                    &u16::try_from(txid)
                        .expect("caller count fits u16")
                        .to_be_bytes(),
                );
                start.wait().await;
                forwarder.resolve(&query).await
            });
        }
        start.wait().await;
        upstream.entered.notified().await;
        let flights = cache.lock().await.singleflight();
        while flights.counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
            tokio::task::yield_now().await;
        }

        // When
        upstream.release.notify_one();
        let mut txids = Vec::with_capacity(CALLERS);
        while let Some(joined) = tasks.join_next().await {
            let response = joined.expect("task").expect("resolve");
            txids.push(u16::from_be_bytes([response[0], response[1]]));
        }

        // Then
        txids.sort_unstable();
        assert_eq!(
            txids,
            (1..=u16::try_from(CALLERS).expect("count")).collect::<Vec<_>>()
        );
        assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(flights.active_len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelled_leader_wakes_all_waiters_to_one_successor_operation() {
        const CALLERS: usize = 128;
        struct CancelUpstream {
            response: Vec<u8>,
            calls: AtomicUsize,
            first_entered: tokio::sync::Notify,
            successor_entered: tokio::sync::Notify,
            release_successor: tokio::sync::Notify,
        }
        #[async_trait]
        impl DnsUpstreamPool for CancelUpstream {
            async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
                let call = self.calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    self.first_entered.notify_one();
                    std::future::pending::<()>().await;
                }
                self.successor_entered.notify_one();
                self.release_successor.notified().await;
                Ok(self.response.clone())
            }
        }

        let upstream = Arc::new(CancelUpstream {
            response: make_a_response([192, 0, 2, 9], 300),
            calls: AtomicUsize::new(0),
            first_entered: tokio::sync::Notify::new(),
            successor_entered: tokio::sync::Notify::new(),
            release_successor: tokio::sync::Notify::new(),
        });
        let forwarder = Arc::new(DnsForwarder::new(
            upstream.clone(),
            test_cache(),
            test_router(),
        ));
        let service = forwarder.cache_service().await;
        let mut leader_query = make_a_query();
        leader_query[0..2].copy_from_slice(&1_u16.to_be_bytes());
        let leader = {
            let forwarder = Arc::clone(&forwarder);
            tokio::spawn(async move { forwarder.resolve(&leader_query).await })
        };
        upstream.first_entered.notified().await;

        let start = Arc::new(tokio::sync::Barrier::new(CALLERS));
        let mut survivors = tokio::task::JoinSet::new();
        for txid in 2..=CALLERS {
            let forwarder = Arc::clone(&forwarder);
            let start = Arc::clone(&start);
            survivors.spawn(async move {
                let mut query = make_a_query();
                query[0..2].copy_from_slice(
                    &u16::try_from(txid)
                        .expect("caller count fits u16")
                        .to_be_bytes(),
                );
                start.wait().await;
                forwarder.resolve(&query).await
            });
        }
        start.wait().await;
        while service.flight_counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
            tokio::task::yield_now().await;
        }

        leader.abort();
        assert!(leader.await.expect_err("cancelled").is_cancelled());
        upstream.successor_entered.notified().await;
        while service.flight_counters().waiters
            < u64::try_from((CALLERS - 1) + (CALLERS - 2)).expect("count")
        {
            tokio::task::yield_now().await;
        }
        upstream.release_successor.notify_one();

        let mut completed = 0;
        while let Some(joined) = survivors.join_next().await {
            joined.expect("task").expect("resolve");
            completed += 1;
        }
        let counters = service.flight_counters();
        assert_eq!(completed, CALLERS - 1);
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
        assert_eq!(counters.leaders, 2);
        assert_eq!(counters.aborts, 1);
        assert_eq!(counters.retries, u64::try_from(CALLERS - 1).expect("count"));
        assert_eq!(service.active_flights(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delayed_preflight_miss_does_not_open_a_second_exchange_after_cache_publish() {
        // Given
        const CALLERS: usize = 128;
        let upstream = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 300)));
        let forwarder = Arc::new(DnsForwarder::new(
            upstream.clone(),
            test_cache(),
            test_router(),
        ));
        let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
        let mut tasks = tokio::task::JoinSet::new();
        for txid in 1..=CALLERS {
            let forwarder = Arc::clone(&forwarder);
            let start = Arc::clone(&start);
            tasks.spawn(async move {
                let mut query = make_a_query();
                query[0..2].copy_from_slice(
                    &u16::try_from(txid)
                        .expect("caller count fits u16")
                        .to_be_bytes(),
                );
                start.wait().await;
                forwarder.resolve(&query).await
            });
        }
        start.wait().await;

        // When
        while let Some(joined) = tasks.join_next().await {
            joined.expect("task").expect("resolve");
        }

        // Then
        assert_eq!(
            upstream.call_count.load(Ordering::SeqCst),
            1,
            "a caller delayed after its cache miss opened a second exchange"
        );
    }

    #[tokio::test]
    async fn forwarding_hot_path_is_not_serialized_by_compatibility_cache_mutex() {
        let cache = test_cache();
        let forwarder = DnsForwarder::new(
            Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 3], 300))),
            cache.clone(),
            test_router(),
        );
        let _service = forwarder.cache_service().await;
        let _compatibility_guard = cache.lock().await;

        let result =
            tokio::time::timeout(Duration::from_secs(1), forwarder.resolve(&make_a_query()))
                .await
                .expect("compatibility mutex must not block service")
                .expect("resolve");

        assert_eq!(&result[result.len() - 4..], &[192, 0, 2, 3]);
    }

    /// Mock upstream that always fails (serve-stale tests).
    struct FailUpstream;

    #[async_trait]
    impl DnsUpstreamPool for FailUpstream {
        async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("upstream down")
        }
    }

    /// Fill the cache with a 1-second-TTL answer, let it expire, then
    /// resolve through a failing upstream — the stale entry must be served
    /// (RFC 8767) with TTLs rewritten to SERVE_STALE_TTL_SECS.
    #[tokio::test]
    async fn test_serve_stale_on_upstream_failure() {
        let response = make_a_response([93, 184, 216, 34], 1);
        let cache = test_cache();
        let query = make_a_query();
        let fwd_ok = DnsForwarder::new(
            Arc::new(MockUpstream::new(response)),
            cache.clone(),
            test_router(),
        );
        fwd_ok.resolve(&query).await.expect("initial resolve");
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

        let fwd_fail = DnsForwarder::new(Arc::new(FailUpstream), cache, test_router());
        let stale = fwd_fail.resolve(&query).await.expect("stale served");
        assert!(stale.windows(4).any(|w| w == [93, 184, 216, 34]));
        assert_eq!(extract_min_ttl(&stale), SERVE_STALE_TTL_SECS);
    }

    /// A SERVFAIL answer must not shadow a recently-expired positive entry.
    #[tokio::test]
    async fn test_serve_stale_on_servfail() {
        let mut servfail = make_a_response([93, 184, 216, 34], 1);
        servfail[3] = 0x82; // RCODE = SERVFAIL
        let cache = test_cache();
        let query = make_a_query();
        let fwd_ok = DnsForwarder::new(
            Arc::new(MockUpstream::new(make_a_response([93, 184, 216, 34], 1))),
            cache.clone(),
            test_router(),
        );
        fwd_ok.resolve(&query).await.expect("initial resolve");
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

        let fwd_fail =
            DnsForwarder::new(Arc::new(MockUpstream::new(servfail)), cache, test_router());
        let stale = fwd_fail.resolve(&query).await.expect("stale served");
        assert!(stale.windows(4).any(|w| w == [93, 184, 216, 34]));
    }

    /// Hot entries nearing expiry trigger a deduplicated background refresh.
    #[tokio::test]
    async fn test_stale_while_revalidate_refresh() {
        let response = make_a_response([93, 184, 216, 34], 2);
        let mock = Arc::new(MockUpstream::new(response));
        let forwarder = DnsForwarder::new(mock.clone(), test_cache(), test_router());
        let query = make_a_query();

        forwarder.resolve(&query).await.expect("initial resolve");
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

        // Wait until remaining TTL (2s) drops to the <=10% threshold.
        tokio::time::sleep(std::time::Duration::from_millis(1900)).await;
        // This lookup is a cache hit that should kick off a refresh.
        forwarder.resolve(&query).await.expect("cache hit");
        // The refresh happens in the background; poll briefly.
        let mut calls = 1;
        for _ in 0..20 {
            calls = mock.call_count.load(Ordering::SeqCst);
            if calls >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(calls, 2, "background refresh should re-query upstream");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hot_near_expiry_hits_own_one_refresh_task_and_close_cleans_it() {
        const CALLERS: usize = 128;
        struct RefreshUpstream {
            response: Vec<u8>,
            calls: AtomicUsize,
            refresh_entered: tokio::sync::Notify,
        }
        #[async_trait]
        impl DnsUpstreamPool for RefreshUpstream {
            async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
                let call = self.calls.fetch_add(1, Ordering::SeqCst);
                if call > 0 {
                    self.refresh_entered.notify_one();
                    std::future::pending::<()>().await;
                }
                Ok(self.response.clone())
            }
        }

        let upstream = Arc::new(RefreshUpstream {
            response: make_a_response([192, 0, 2, 10], 2),
            calls: AtomicUsize::new(0),
            refresh_entered: tokio::sync::Notify::new(),
        });
        let forwarder = Arc::new(DnsForwarder::new(
            upstream.clone(),
            test_cache(),
            test_router(),
        ));
        let service = forwarder.cache_service().await;
        forwarder.resolve(&make_a_query()).await.expect("prime");
        tokio::time::sleep(Duration::from_millis(1900)).await;

        let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
        let mut callers = tokio::task::JoinSet::new();
        for _ in 0..CALLERS {
            let forwarder = Arc::clone(&forwarder);
            let start = Arc::clone(&start);
            callers.spawn(async move {
                start.wait().await;
                forwarder.resolve(&make_a_query()).await
            });
        }
        start.wait().await;
        while let Some(joined) = callers.join_next().await {
            joined.expect("task").expect("cache hit");
        }
        upstream.refresh_entered.notified().await;

        assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
        assert_eq!(service.refresh_task_count(), 1);
        assert_eq!(service.active_flights(), 1);
        service.close_refresh_tasks().await;
        assert_eq!(service.refresh_task_count(), 0);
        assert_eq!(service.active_flights(), 0);
    }

    /// RFC 2308 §5: negative TTL = min(SOA TTL, SOA MINIMUM).
    #[test]
    fn test_extract_soa_negative_ttl() {
        // NXDOMAIN with authority SOA (ttl=300, minimum=60).
        let mut resp = vec![
            0x00, 0x00, // ID
            0x81, 0x83, // QR + RCODE=NXDOMAIN
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x01, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        // Question: example.com A IN
        for label in ["example", "com"] {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Authority SOA: name ptr, type SOA, class IN, ttl 300, rdata
        // root mname/rname + serial/refresh/retry/expire + minimum 60.
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0x00, 0x06, 0x00, 0x01]);
        resp.extend_from_slice(&300u32.to_be_bytes());
        let mut rdata = vec![0x00, 0x00]; // MNAME, RNAME (root)
        for v in [1u32, 7200, 3600, 1209600, 60] {
            rdata.extend_from_slice(&v.to_be_bytes());
        }
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);

        assert_eq!(extract_soa_negative_ttl(&resp, 60), 60);
        // No authority section → default.
        let plain = make_a_response([1, 1, 1, 1], 300);
        assert_eq!(extract_soa_negative_ttl(&plain, 42), 42);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let response = make_a_response([93, 184, 216, 34], 300);
        let mock = Arc::new(MockUpstream::new(response.clone()));
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        );

        let query = make_a_query();

        let result1 = forwarder.resolve(&query).await.expect("first resolve");
        assert_eq!(result1, response);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

        let result2 = forwarder.resolve(&query).await.expect("second resolve");
        assert_eq!(result2, response);
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            1,
            "upstream should not be called again"
        );
    }

    #[tokio::test]
    async fn test_cache_hit_rewrites_transaction_id() {
        // Build a response whose ID does not match the query ID.  The forwarder
        // must rewrite the response ID to match each query so that standard
        // resolvers (glibc/c-ares) accept cached answers.
        let mut response = make_a_response([93, 184, 216, 34], 300);
        response[0] = 0xBE;
        response[1] = 0xEF;

        let mock = Arc::new(MockUpstream::new(response.clone()));
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        );

        let mut query = make_a_query();
        query[0] = 0xAB;
        query[1] = 0xCD;

        let result1 = forwarder.resolve(&query).await.expect("first resolve");
        assert_eq!(&result1[0..2], &[0xAB, 0xCD]);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

        let result2 = forwarder.resolve(&query).await.expect("second resolve");
        assert_eq!(&result2[0..2], &[0xAB, 0xCD]);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_forward_basic() {
        let response = make_a_response([8, 8, 8, 8], 600);
        let mock = Arc::new(MockUpstream::new(response.clone()));
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        );

        let result = forwarder.resolve(&make_a_query()).await.expect("resolve");
        assert_eq!(result, response);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_routing_respects_rules() {
        let response_custom = make_a_response([10, 0, 0, 1], 300);
        let response_default = make_a_response([8, 8, 8, 8], 300);

        // Mock that returns different responses based on upstream name
        struct RoutingMock {
            custom_resp: Vec<u8>,
            default_resp: Vec<u8>,
            calls: AtomicUsize,
        }
        #[async_trait]
        impl DnsUpstreamPool for RoutingMock {
            async fn query(
                &self,
                upstream_name: &str,
                _raw_query: &[u8],
            ) -> anyhow::Result<Vec<u8>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                match upstream_name {
                    "custom" => Ok(self.custom_resp.clone()),
                    _ => Ok(self.default_resp.clone()),
                }
            }
        }

        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                rules: vec![DnsRule {
                    domain: "full:custom.test".into(),
                    upstream: "custom".into(),
                }],
                fallback: "default".into(),
                ..Default::default()
            })
            .expect("router"),
        );

        let mock = Arc::new(RoutingMock {
            custom_resp: response_custom.clone(),
            default_resp: response_default.clone(),
            calls: AtomicUsize::new(0),
        });
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            router,
        );

        let query = build_dns_query("custom.test", 1);
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(result, response_custom);

        let query2 = build_dns_query("other.test", 1);
        let result2 = forwarder.resolve(&query2).await.expect("resolve");
        assert_eq!(result2, response_default);
    }

    #[tokio::test]
    async fn test_prefetch_warms_cache() {
        let response = make_a_response([1, 2, 3, 4], 300);
        let mock = Arc::new(MockUpstream::new(response.clone()));
        let cache = test_cache();
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            cache.clone(),
            test_router(),
        );

        let domains: Vec<String> = vec!["example.com".into()];
        forwarder.prefetch(&domains);

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let query = make_a_query();
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(result, response);

        // The upstream should have been called at least once (by prefetch),
        // but resolve itself may or may not call it depending on timing
        let calls = mock.call_count.load(Ordering::SeqCst);
        assert!(
            calls >= 1,
            "expected at least 1 upstream call for prefetch, got {}",
            calls
        );
    }

    #[test]
    fn test_parse_dns_question_a_record() {
        let query = build_dns_query("www.example.com", 1);
        let (domain, qtype) = parse_dns_question(&query).expect("parse");
        assert_eq!(domain, "www.example.com");
        assert_eq!(qtype, 1); // A
    }

    #[test]
    fn test_parse_dns_question_aaaa_record() {
        let query = build_dns_query("ipv6.test.org", 28);
        let (domain, qtype) = parse_dns_question(&query).expect("parse");
        assert_eq!(domain, "ipv6.test.org");
        assert_eq!(qtype, 28); // AAAA
    }

    #[test]
    fn test_parse_dns_question_single_label() {
        let query = build_dns_query("localhost", 1);
        let (domain, qtype) = parse_dns_question(&query).expect("parse");
        assert_eq!(domain, "localhost");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn test_parse_dns_question_truncated() {
        let short = vec![0u8; 10];
        assert!(parse_dns_question(&short).is_none());
    }

    #[test]
    fn test_extract_min_ttl_single_answer() {
        let resp = make_a_response([8, 8, 8, 8], 300);
        let ttl = extract_min_ttl(&resp);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn test_extract_min_ttl_no_answers() {
        // Response with ANCOUNT=0
        let resp = vec![
            0x00, 0x01, // ID
            0x81, 0x83, // Flags: NXDOMAIN
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        let ttl = extract_min_ttl(&resp);
        assert_eq!(ttl, 60, "default TTL when no answers present");
    }

    #[test]
    fn test_extract_min_ttl_short_response() {
        let short = vec![0u8; 5];
        assert_eq!(extract_min_ttl(&short), 60);
    }

    #[test]
    fn test_cache_key_format() {
        assert_eq!(dns_cache_key("example.com", 1), "example.com:1");
        assert_eq!(dns_cache_key("test.org", 28), "test.org:28");
    }

    #[test]
    fn test_build_and_parse_roundtrip() {
        let domains = vec![
            "google.com",
            "sub.domain.example.org",
            "localhost",
            "a.b.c.d.e.f.g.h.example.com",
        ];

        for domain in domains {
            for qtype in [1u16, 28u16, 5u16] {
                let query = build_dns_query(domain, qtype);
                let (parsed_domain, parsed_qtype) =
                    parse_dns_question(&query).expect("roundtrip parse");
                assert_eq!(
                    parsed_domain, domain,
                    "domain mismatch for {} QTYPE={}",
                    domain, qtype
                );
                assert_eq!(parsed_qtype, qtype, "qtype mismatch for {}", domain);
            }
        }
    }

    #[test]
    fn test_effective_cache_ttl_override() {
        assert_eq!(effective_cache_ttl(600, 30), 600);
        assert_eq!(effective_cache_ttl(0, 30), 30);
        assert_eq!(effective_cache_ttl(0, 0), 1);
    }

    #[test]
    fn test_rewrite_answer_ttls_overrides_wire() {
        let mut resp = make_a_response([1, 2, 3, 4], 30);
        assert_eq!(extract_min_ttl(&resp), 30);
        rewrite_answer_ttls(&mut resp, 600);
        assert_eq!(extract_min_ttl(&resp), 600);
    }

    #[tokio::test]
    async fn test_optimistic_cache_ttl_overrides_answer_ttl() {
        // Upstream answers with TTL=30; forwarder configured for 600.
        let upstream_resp = make_a_response([9, 9, 9, 9], 30);
        let mock = Arc::new(MockUpstream::new(upstream_resp));
        let cache = test_cache();
        let forwarder = DnsForwarder::new(
            mock as Arc<dyn DnsUpstreamPool>,
            cache.clone(),
            test_router(),
        )
        .with_cache_ttl(600);

        let query = make_a_query();
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(
            extract_min_ttl(&result),
            600,
            "client-visible wire TTL overridden"
        );

        {
            let guard = cache.lock().await;
            let entries = guard.positive_entries_for_test();
            let entry = entries.first().expect("cached");
            assert_eq!(entry.min_ttl, 600);
            assert_eq!(extract_min_ttl(&entry.response), 600);
            // Lifetime should be ~600s, not 30s.
            let remaining = entry.remaining_ttl_secs();
            assert!(
                (590..=600).contains(&remaining),
                "cache lifetime uses optimistic_cache_ttl, got {remaining}"
            );
        }
    }

    #[tokio::test]
    async fn test_request_reject_skips_upstream() {
        use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

        let mock = Arc::new(MockUpstream::new(make_a_response([1, 1, 1, 1], 60)));
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: vec![DnsRequestRule {
                        conditions: vec![DnsCond::Qtype {
                            not: false,
                            types: vec![65], // HTTPS
                        }],
                        action: DnsRequestAction::Reject,
                    }],
                    fallback: DnsRequestAction::Upstream("default".into()),
                },
                ..Default::default()
            })
            .unwrap(),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            router,
        );

        let query = build_dns_query("example.com", 65);
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            0,
            "reject must not dial"
        );
        assert_eq!(
            u16::from_be_bytes([result[6], result[7]]),
            0,
            "empty ANCOUNT"
        );
    }

    #[tokio::test]
    async fn test_qtype_routes_to_named_upstream() {
        use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

        struct NameMock {
            last: std::sync::Mutex<String>,
            a_resp: Vec<u8>,
            aaaa_resp: Vec<u8>,
        }
        #[async_trait]
        impl DnsUpstreamPool for NameMock {
            async fn query(
                &self,
                upstream_name: &str,
                _raw_query: &[u8],
            ) -> anyhow::Result<Vec<u8>> {
                *self.last.lock().unwrap() = upstream_name.to_string();
                if upstream_name == "v6dns" {
                    Ok(self.aaaa_resp.clone())
                } else {
                    Ok(self.a_resp.clone())
                }
            }
        }

        let mock = Arc::new(NameMock {
            last: std::sync::Mutex::new(String::new()),
            a_resp: make_a_response([1, 2, 3, 4], 60),
            aaaa_resp: make_a_response([9, 9, 9, 9], 60),
        });
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: vec![DnsRequestRule {
                        conditions: vec![DnsCond::Qtype {
                            not: false,
                            types: vec![28],
                        }],
                        action: DnsRequestAction::Upstream("v6dns".into()),
                    }],
                    fallback: DnsRequestAction::Upstream("default".into()),
                },
                ..Default::default()
            })
            .unwrap(),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            router,
        )
        .with_strategy(honk_config::dns::DnsStrategy::Both);

        let q_a = build_dns_query("example.com", 1);
        let _ = forwarder.resolve(&q_a).await.unwrap();
        assert_eq!(mock.last.lock().unwrap().as_str(), "default");

        let q_aaaa = build_dns_query("example.com", 28);
        let _ = forwarder.resolve(&q_aaaa).await.unwrap();
        assert_eq!(mock.last.lock().unwrap().as_str(), "v6dns");
    }

    #[tokio::test]
    async fn test_response_requery_switches_upstream() {
        use honk_config::dns::{
            DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
            DnsResponseRule,
        };

        struct SeqMock {
            calls: AtomicUsize,
            polluted: Vec<u8>,
            clean: Vec<u8>,
        }
        #[async_trait]
        impl DnsUpstreamPool for SeqMock {
            async fn query(
                &self,
                upstream_name: &str,
                _raw_query: &[u8],
            ) -> anyhow::Result<Vec<u8>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if upstream_name == "googledns" {
                    Ok(self.clean.clone())
                } else {
                    Ok(self.polluted.clone())
                }
            }
        }

        let mock = Arc::new(SeqMock {
            calls: AtomicUsize::new(0),
            polluted: make_a_response([10, 0, 0, 1], 60), // private → trigger requery
            clean: make_a_response([8, 8, 8, 8], 60),
        });
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: vec![],
                    fallback: DnsRequestAction::Upstream("alidns".into()),
                },
                response: DnsResponseRouting {
                    rules: vec![DnsResponseRule {
                        conditions: vec![DnsCond::Ip {
                            not: false,
                            cidrs: vec!["10.0.0.0/8".into()],
                            geoip: vec![],
                        }],
                        action: DnsResponseAction::Upstream("googledns".into()),
                    }],
                    fallback: DnsResponseAction::Accept,
                },
                ..Default::default()
            })
            .unwrap(),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            router,
        );

        let query = make_a_query();
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 2, "polluted then clean");
        assert_eq!(&result[result.len() - 4..], &[8, 8, 8, 8]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_response_requery_is_one_logical_flight() {
        use honk_config::dns::{
            DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
            DnsResponseRule,
        };

        const CALLERS: usize = 128;
        struct RequeryUpstream {
            initial_calls: AtomicUsize,
            fallback_calls: AtomicUsize,
            initial_entered: tokio::sync::Notify,
            initial_release: tokio::sync::Notify,
            polluted: Vec<u8>,
            clean: Vec<u8>,
        }
        #[async_trait]
        impl DnsUpstreamPool for RequeryUpstream {
            async fn query(&self, upstream: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
                if upstream == "fallback" {
                    self.fallback_calls.fetch_add(1, Ordering::SeqCst);
                    return Ok(self.clean.clone());
                }
                self.initial_calls.fetch_add(1, Ordering::SeqCst);
                self.initial_entered.notify_one();
                self.initial_release.notified().await;
                Ok(self.polluted.clone())
            }
        }

        let upstream = Arc::new(RequeryUpstream {
            initial_calls: AtomicUsize::new(0),
            fallback_calls: AtomicUsize::new(0),
            initial_entered: tokio::sync::Notify::new(),
            initial_release: tokio::sync::Notify::new(),
            polluted: make_a_response([10, 0, 0, 1], 60),
            clean: make_a_response([8, 8, 8, 8], 60),
        });
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: Vec::new(),
                    fallback: DnsRequestAction::Upstream("initial".into()),
                },
                response: DnsResponseRouting {
                    rules: vec![DnsResponseRule {
                        conditions: vec![DnsCond::Ip {
                            not: false,
                            cidrs: vec!["10.0.0.0/8".into()],
                            geoip: Vec::new(),
                        }],
                        action: DnsResponseAction::Upstream("fallback".into()),
                    }],
                    fallback: DnsResponseAction::Accept,
                },
                ..Default::default()
            })
            .expect("router"),
        );
        let cache = test_cache();
        let flights = cache.lock().await.singleflight();
        let forwarder = Arc::new(DnsForwarder::new(upstream.clone(), cache, router));
        let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
        let mut tasks = tokio::task::JoinSet::new();
        for txid in 1..=CALLERS {
            let forwarder = Arc::clone(&forwarder);
            let start = Arc::clone(&start);
            tasks.spawn(async move {
                let mut query = make_a_query();
                query[0..2].copy_from_slice(
                    &u16::try_from(txid)
                        .expect("caller count fits u16")
                        .to_be_bytes(),
                );
                start.wait().await;
                forwarder.resolve(&query).await
            });
        }
        start.wait().await;
        upstream.initial_entered.notified().await;
        while flights.counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
            tokio::task::yield_now().await;
        }

        upstream.initial_release.notify_one();
        let mut txids = Vec::with_capacity(CALLERS);
        while let Some(joined) = tasks.join_next().await {
            let response = joined.expect("task").expect("resolve");
            assert_eq!(&response[response.len() - 4..], &[8, 8, 8, 8]);
            txids.push(u16::from_be_bytes([response[0], response[1]]));
        }
        txids.sort_unstable();
        assert_eq!(
            txids,
            (1..=u16::try_from(CALLERS).expect("count")).collect::<Vec<_>>()
        );
        assert_eq!(upstream.initial_calls.load(Ordering::SeqCst), 1);
        assert_eq!(upstream.fallback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(flights.active_len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn response_requery_error_stays_unpublished_and_waiters_retry_once() {
        use honk_config::dns::{
            DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
            DnsResponseRule,
        };

        const CALLERS: usize = 128;
        struct RetryUpstream {
            initial_calls: AtomicUsize,
            fallback_calls: AtomicUsize,
            initial_entered: tokio::sync::Notify,
            initial_release: tokio::sync::Notify,
            successor_entered: tokio::sync::Notify,
            successor_release: tokio::sync::Notify,
            polluted: Vec<u8>,
            clean: Vec<u8>,
        }
        #[async_trait]
        impl DnsUpstreamPool for RetryUpstream {
            async fn query(&self, upstream: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
                if upstream == "fallback" {
                    let call = self.fallback_calls.fetch_add(1, Ordering::SeqCst);
                    if call == 0 {
                        anyhow::bail!("first fallback failed");
                    }
                    return Ok(self.clean.clone());
                }
                let call = self.initial_calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    self.initial_entered.notify_one();
                    self.initial_release.notified().await;
                } else if call == 1 {
                    self.successor_entered.notify_one();
                    self.successor_release.notified().await;
                }
                Ok(self.polluted.clone())
            }
        }

        let upstream = Arc::new(RetryUpstream {
            initial_calls: AtomicUsize::new(0),
            fallback_calls: AtomicUsize::new(0),
            initial_entered: tokio::sync::Notify::new(),
            initial_release: tokio::sync::Notify::new(),
            successor_entered: tokio::sync::Notify::new(),
            successor_release: tokio::sync::Notify::new(),
            polluted: make_a_response([10, 0, 0, 1], 60),
            clean: make_a_response([8, 8, 4, 4], 60),
        });
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: Vec::new(),
                    fallback: DnsRequestAction::Upstream("initial".into()),
                },
                response: DnsResponseRouting {
                    rules: vec![DnsResponseRule {
                        conditions: vec![DnsCond::Ip {
                            not: false,
                            cidrs: vec!["10.0.0.0/8".into()],
                            geoip: Vec::new(),
                        }],
                        action: DnsResponseAction::Upstream("fallback".into()),
                    }],
                    fallback: DnsResponseAction::Accept,
                },
                ..Default::default()
            })
            .expect("router"),
        );
        let forwarder = Arc::new(DnsForwarder::new(upstream.clone(), test_cache(), router));
        let service = forwarder.cache_service().await;
        let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..CALLERS {
            let forwarder = Arc::clone(&forwarder);
            let start = Arc::clone(&start);
            tasks.spawn(async move {
                start.wait().await;
                forwarder.resolve(&make_a_query()).await
            });
        }
        start.wait().await;
        upstream.initial_entered.notified().await;
        while service.flight_counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
            tokio::task::yield_now().await;
        }
        upstream.initial_release.notify_one();
        upstream.successor_entered.notified().await;
        while service.flight_counters().waiters
            < u64::try_from((CALLERS - 1) + (CALLERS - 2)).expect("count")
        {
            tokio::task::yield_now().await;
        }
        upstream.successor_release.notify_one();

        let mut successes = 0;
        let mut failures = 0;
        while let Some(joined) = tasks.join_next().await {
            match joined.expect("task") {
                Ok(response) => {
                    assert_eq!(&response[response.len() - 4..], &[8, 8, 4, 4]);
                    successes += 1;
                }
                Err(_) => failures += 1,
            }
        }
        let counters = service.flight_counters();
        assert_eq!((successes, failures), (CALLERS - 1, 1));
        assert_eq!(upstream.initial_calls.load(Ordering::SeqCst), 2);
        assert_eq!(upstream.fallback_calls.load(Ordering::SeqCst), 2);
        assert_eq!(counters.leaders, 2);
        assert_eq!(counters.aborts, 1);
        assert_eq!(counters.retries, u64::try_from(CALLERS - 1).expect("count"));
        assert_eq!(service.active_flights(), 0);
    }

    #[tokio::test]
    async fn test_response_requery_stops_at_depth_limit() {
        use honk_config::dns::{
            DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
            DnsResponseRule,
        };

        struct RecordingUpstream {
            calls: std::sync::Mutex<Vec<String>>,
        }

        #[async_trait]
        impl DnsUpstreamPool for RecordingUpstream {
            async fn query(
                &self,
                upstream_name: &str,
                _raw_query: &[u8],
            ) -> anyhow::Result<Vec<u8>> {
                self.calls.lock().unwrap().push(upstream_name.to_string());
                let last_octet = match upstream_name {
                    "default" => 1,
                    "one" => 2,
                    "two" => 3,
                    "three" => 4,
                    _ => 255,
                };
                Ok(make_a_response([192, 0, 2, last_octet], 60))
            }
        }

        let response_rules = [("default", "one"), ("one", "two"), ("two", "three")]
            .into_iter()
            .map(|(from, to)| DnsResponseRule {
                conditions: vec![DnsCond::Upstream {
                    not: false,
                    names: vec![from.to_string()],
                }],
                action: DnsResponseAction::Upstream(to.to_string()),
            })
            .collect();
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: vec![],
                    fallback: DnsRequestAction::Upstream("default".into()),
                },
                response: DnsResponseRouting {
                    rules: response_rules,
                    fallback: DnsResponseAction::Accept,
                },
                ..Default::default()
            })
            .unwrap(),
        );
        let upstream = Arc::new(RecordingUpstream {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), router);

        let response = forwarder.resolve(&make_a_query()).await.unwrap();

        assert_eq!(
            upstream.calls.lock().unwrap().as_slice(),
            ["default", "one", "two"],
            "depth three is accepted without issuing a fourth exchange"
        );
        assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 3]);
    }

    #[tokio::test]
    async fn test_asis_uses_original_destination() {
        use honk_config::dns::{DnsRequestAction, DnsRequestRouting};

        let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let original_dst = socket.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut request = vec![0u8; 512];
            let (size, peer) = socket.recv_from(&mut request).await.unwrap();
            request.truncate(size);
            let mut response = make_a_response([203, 0, 113, 7], 60);
            response[0..2].copy_from_slice(&request[0..2]);
            socket.send_to(&response, peer).await.unwrap();
        });
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: vec![],
                    fallback: DnsRequestAction::AsIs,
                },
                ..Default::default()
            })
            .unwrap(),
        );
        let forwarder = DnsForwarder::new(Arc::new(FailUpstream), test_cache(), router);
        let query = make_a_query();

        let response = forwarder
            .resolve_with_context(&query, Some(original_dst))
            .await
            .unwrap();
        responder.await.unwrap();

        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(&response[response.len() - 4..], &[203, 0, 113, 7]);
    }

    #[tokio::test]
    async fn test_fixed_domain_ttl_zero_skips_cache() {
        use std::collections::HashMap;

        let response = make_a_response([1, 2, 3, 4], 300);
        let mock = Arc::new(MockUpstream::new(response));
        let cache = test_cache();
        let mut ttl = HashMap::new();
        ttl.insert("example.com".to_string(), 0u32);
        let router = Arc::new(DnsRouter::new_with_fixed_ttl(&DnsRouting::default(), &ttl).unwrap());
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            cache.clone(),
            router,
        );

        let query = make_a_query();
        let _ = forwarder.resolve(&query).await.unwrap();
        assert!(
            cache.lock().await.get("example.com:1").is_none(),
            "fixed_domain_ttl=0 must not cache"
        );
        // Second resolve hits upstream again.
        let _ = forwarder.resolve(&query).await.unwrap();
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_extract_answer_ips_a_record() {
        let resp = make_a_response([1, 2, 3, 4], 60);
        let ips = extract_answer_ips(&resp);
        assert_eq!(ips, vec![IpAddr::from([1, 2, 3, 4])]);
    }

    /// Build an AAAA-record response for example.com with a given IPv6 and TTL.
    fn make_aaaa_response(ip: [u8; 16], ttl: u32) -> Vec<u8> {
        let ttl_bytes = ttl.to_be_bytes();
        let mut v = vec![
            0x00,
            0x00, // ID
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
            // Question: example.com AAAA IN
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
            0x1c, // QTYPE AAAA
            0x00,
            0x01, // QCLASS IN
            // Answer
            0xc0,
            0x0c, // NAME pointer to offset 12
            0x00,
            0x1c, // TYPE AAAA
            0x00,
            0x01, // CLASS IN
            ttl_bytes[0],
            ttl_bytes[1],
            ttl_bytes[2],
            ttl_bytes[3], // TTL
            0x00,
            0x10, // RDLENGTH 16
        ];
        v.extend_from_slice(&ip);
        v
    }

    fn nodata_response(domain: &str, qtype: u16) -> Vec<u8> {
        make_empty_response(&build_dns_query(domain, qtype), domain, qtype)
    }

    fn answer_count(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[6], resp[7]])
    }

    /// Mock upstream answering per query qtype.
    struct QtypeMock {
        a: Vec<u8>,
        aaaa: Vec<u8>,
        call_count: AtomicUsize,
    }

    #[async_trait]
    impl DnsUpstreamPool for QtypeMock {
        async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let (domain, qtype) = parse_dns_question(raw_query).expect("question");
            Ok(match qtype {
                1 => self.a.clone(),
                28 => self.aaaa.clone(),
                _ => make_empty_response(raw_query, &domain, qtype),
            })
        }
    }

    fn qtype_mock(a: Vec<u8>, aaaa: Vec<u8>) -> Arc<QtypeMock> {
        Arc::new(QtypeMock {
            a,
            aaaa,
            call_count: AtomicUsize::new(0),
        })
    }

    const TEST_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    #[tokio::test]
    async fn test_only_strategy_filters_at_request_time() {
        let mock = qtype_mock(
            make_a_response([10, 0, 0, 1], 300),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::Ipv4Only);

        let resp = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert_eq!(answer_count(&resp), 0, "AAAA must be answered NODATA");
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            0,
            "filtered query must never reach upstream"
        );
    }

    #[tokio::test]
    async fn test_prefer_ipv4_suppresses_aaaa_when_a_exists() {
        let mock = qtype_mock(
            make_a_response([10, 0, 0, 1], 300),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::PreferIpv4);

        // Prime the A cache with real answers.
        let a_resp = forwarder.resolve(&make_a_query()).await.unwrap();
        assert!(answer_count(&a_resp) > 0);

        // AAAA is forwarded to upstream but suppressed at response time.
        let aaaa_resp = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert_eq!(
            answer_count(&aaaa_resp),
            0,
            "AAAA must be suppressed when A answers exist"
        );
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            2,
            "A + AAAA; the prefer check must hit the cache, not upstream"
        );
    }

    #[tokio::test]
    async fn test_prefer_ipv4_returns_aaaa_when_no_a() {
        let mock = qtype_mock(
            nodata_response("example.com", 1),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::PreferIpv4);

        let resp = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert_eq!(
            answer_count(&resp),
            1,
            "AAAA must be returned when no A answers exist"
        );
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            2,
            "AAAA + sibling A probe"
        );

        // Cache-hit path: AAAA and the sibling's NODATA are both cached.
        let resp2 = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert_eq!(answer_count(&resp2), 1);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_prefer_ipv4_never_probes_for_a_queries() {
        let mock = qtype_mock(
            make_a_response([10, 0, 0, 1], 300),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::PreferIpv4);

        let resp = forwarder.resolve(&make_a_query()).await.unwrap();
        assert_eq!(answer_count(&resp), 1);
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            1,
            "preferred qtype must not trigger a sibling probe"
        );
    }

    #[tokio::test]
    async fn test_prefer_ipv6_suppresses_a_when_aaaa_exists() {
        let mock = qtype_mock(
            make_a_response([10, 0, 0, 1], 300),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::PreferIpv6);

        // Prime the AAAA cache.
        let aaaa_resp = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert!(answer_count(&aaaa_resp) > 0);

        let a_resp = forwarder.resolve(&make_a_query()).await.unwrap();
        assert_eq!(
            answer_count(&a_resp),
            0,
            "A must be suppressed when AAAA answers exist"
        );
    }

    /// A cached NXDOMAIN must be answered as NXDOMAIN (rcode 3), never
    /// upgraded to SERVFAIL — the two have opposite client semantics.
    #[tokio::test]
    async fn test_negative_cache_returns_nxdomain_not_servfail() {
        let mut nx = make_a_response([93, 184, 216, 34], 60);
        nx[3] = 0x83; // QR + RA + NXDOMAIN
        let mock = Arc::new(MockUpstream::new(nx));
        let cache = test_cache();
        let forwarder = DnsForwarder::new(mock.clone(), cache, test_router());
        let query = make_a_query();

        let resp = forwarder.resolve(&query).await.expect("first nxdomain");
        assert_eq!(resp[3] & 0x0f, 3);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

        let resp2 = forwarder.resolve(&query).await.expect("cached nxdomain");
        assert_eq!(resp2[3] & 0x0f, 3, "cached negative must stay NXDOMAIN");
        assert_eq!(resp2[0..2], query[0..2], "txid must match the query");
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            1,
            "negative hit must not re-query upstream"
        );
    }

    /// A cached SERVFAIL stays SERVFAIL (rcode 2) on later hits.
    #[tokio::test]
    async fn test_negative_cache_keeps_servfail_rcode() {
        let mut sf = make_a_response([93, 184, 216, 34], 1);
        sf[3] = 0x82; // QR + RA + SERVFAIL
        let mock = Arc::new(MockUpstream::new(sf));
        let cache = test_cache();
        let forwarder = DnsForwarder::new(mock.clone(), cache, test_router());
        let query = make_a_query();

        let _ = forwarder.resolve(&query).await;
        // Second hit: still rcode 2, no extra upstream call.
        let resp2 = forwarder.resolve(&query).await.expect("cached servfail");
        assert_eq!(resp2[3] & 0x0f, 2);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }
}
