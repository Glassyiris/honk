use std::net::SocketAddr;

use tracing::debug;

use crate::dns::query::IngressProfile;
use honk_config::dns::DnsStrategy;

use super::DnsForwarder;
use super::message::build_dns_query;
use super::response::{dns_cache_key, make_empty_response, qtype_name, response_has_family_ips};

impl DnsForwarder {
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
}
