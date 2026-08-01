use std::net::SocketAddr;

use crate::dns::outcome::{DnsOutcome, OutcomeStatus, ResponseClass};
use crate::dns::query::IngressProfile;

use super::{DnsForwardError, DnsForwarder, ResolveMode};

impl DnsForwarder {
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
        let result = crate::dns::engine::pipeline::resolve(
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
                    (OutcomeStatus::Rejected, _) => crate::stats::DnsStatEvent::OutcomeRejected,
                    (OutcomeStatus::Accepted, ResponseClass::Positive) => {
                        crate::stats::DnsStatEvent::OutcomePositive
                    }
                    (OutcomeStatus::Accepted, ResponseClass::Nodata) => {
                        crate::stats::DnsStatEvent::OutcomeNodata
                    }
                    (OutcomeStatus::Accepted, ResponseClass::Nxdomain) => {
                        crate::stats::DnsStatEvent::OutcomeNxdomain
                    }
                    (OutcomeStatus::Accepted, ResponseClass::Servfail) => {
                        crate::stats::DnsStatEvent::OutcomeServfail
                    }
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
                    DnsForwardError::Overloaded => "overloaded",
                };
                tracing::debug!(error_kind, "DNS resolution failed");
            }
        }
        result
    }
}
