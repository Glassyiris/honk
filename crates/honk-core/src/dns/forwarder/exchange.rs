use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tracing::{debug, trace};

use crate::dns::cache::{DnsCacheService, PublicationEpoch};
use crate::dns::engine::{DnsEngine, PreparedQuery};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeParts, OutcomeStatus, Provenance};
use crate::dns::planner::RequestScope;
use crate::dns::query::IngressProfile;
use crate::dns::response::ResponseTemplate;
use honk_ebpf_common::DAE_BYPASS_MARK;

use super::message::{build_dns_query, new_asis_socket_with_mark};
use super::ttl::{SERVE_STALE_TTL_SECS, patch_txid, rewrite_answer_ttls};
use super::{DnsForwardError, DnsForwarder, ResolveMode};

impl DnsForwarder {
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
            response_class: crate::dns::engine::classify_response(&reusable),
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
            let result = crate::dns::engine::pipeline::resolve_with_owner(
                &this,
                &query,
                original_dst,
                ingress,
                true,
                ResolveMode::Compatibility,
                crate::dns::engine::pipeline::ResolveExecution::refresh(owner, publication_epoch),
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
            let forwarder = self.background_clone();
            let _ = self.prefetch_tasks.spawn(async move {
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
