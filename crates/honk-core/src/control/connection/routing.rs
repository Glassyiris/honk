use super::handoff::HandoffResult;
use crate::control::*;
pub(super) fn connection_chains(mut selection_chain: Vec<String>, node_name: &str) -> Vec<String> {
    if selection_chain.last().map(String::as_str) != Some(node_name) {
        selection_chain.push(node_name.to_owned());
    }
    selection_chain.reverse();
    selection_chain
}

#[cfg(any(feature = "ebpf", test))]
pub(super) fn final_udp_rule_mark(
    routed_direct: bool,
    final_outbound: &str,
    routed_mark: u32,
) -> u32 {
    if final_outbound == "direct" && !routed_direct {
        0
    } else {
        routed_mark
    }
}

impl ControlPlaneHandle {
    /// Verify that a sniffed domain actually resolves to the given IP address.
    ///
    /// This is used by `dial_mode: domain` to prevent routing based on a fake
    /// SNI sent by the client. Both IPv4 and IPv6 results are checked.
    ///
    /// When the connection is dual-stack but our resolver only returns the
    /// other family (common when the DNS strategy suppresses AAAA — e.g.
    /// `ipversion_prefer: 4` with A answers present, or an only-mode), the
    /// check **trusts the SNI** instead of discarding it.
    /// Falling back to IP-only would mis-route CDN IPv6 (e.g. `tracker.m-team.cc`
    /// on Cloudflare AAAA) via `dport(443) → proxy` despite
    /// `domain(keyword: m-team) → direct`.
    pub(super) async fn verify_domain_reality(
        &self,
        domain: &str,
        expected: std::net::IpAddr,
    ) -> bool {
        let dns_timeout = std::time::Duration::from_millis(
            self.config.read().await.global.dns_resolve_timeout_ms,
        );
        match tokio::time::timeout(dns_timeout, self.dns_resolver.resolve(domain)).await {
            Ok(Ok(resolved)) => {
                match domain_reality_outcome(expected, &resolved.ipv4, &resolved.ipv6) {
                    RealityOutcome::ExactMatch => true,
                    RealityOutcome::OtherFamilyOnly => {
                        debug!(
                            "Domain reality check: {} has no records for {}; other family present — trusting SNI (got v4={:?} v6={:?})",
                            domain, expected, resolved.ipv4, resolved.ipv6
                        );
                        true
                    }
                    RealityOutcome::Mismatch => {
                        debug!(
                            "Domain reality check failed: {} does not resolve to {} (got {:?} {:?})",
                            domain, expected, resolved.ipv4, resolved.ipv6
                        );
                        false
                    }
                }
            }
            Ok(Err(e)) => {
                debug!(
                    "Domain reality check failed: unable to resolve {}: {}",
                    domain, e
                );
                false
            }
            Err(_) => {
                debug!("Domain reality check timed out for {}", domain);
                false
            }
        }
    }

    pub(super) fn should_reroute_sniffed_domain(
        dial_mode: DialMode,
        domain: Option<&str>,
        handoff: Option<&HandoffResult>,
    ) -> bool {
        !matches!(dial_mode, DialMode::Ip)
            && domain.is_some()
            && handoff.is_some_and(|handoff| {
                handoff.must == 0 && handoff.outbound != OutboundIndex::Block as u8
            })
    }

    pub(super) fn should_write_sniffed_domain_bitmap(
        handoff: Option<&HandoffResult>,
        reroute_by_sniffed_domain: bool,
    ) -> bool {
        reroute_by_sniffed_domain
            || handoff
                .map(|handoff| handoff.outbound == OutboundIndex::ControlPlaneRouting as u8)
                .unwrap_or(true)
    }

    /// Publish the matched sniffed-domain bitmap so later route-time
    /// decisions can use the learned destination IP. Best-effort: a write
    /// failure never fails the flow.
    pub(super) async fn push_sniffed_domain_bitmap(
        &self,
        conn_info: &ConnectionInfo,
        domain: &str,
        dst_ip: std::net::IpAddr,
    ) {
        let (rule_name, bitmaps) = {
            let router = self.router.read().await;
            match router.route_full(conn_info) {
                Some(matched) => {
                    let rule_name = matched.rule_name.to_string();
                    let bitmaps = {
                        let db = DOMAIN_BITMAPS.read();
                        db.get(&rule_name).cloned().unwrap_or_default()
                    };
                    (rule_name, bitmaps)
                }
                None => return,
            }
        };
        if bitmaps.is_empty() {
            return;
        }
        let mut merged = DomainRouting::default();
        for bm in &bitmaps {
            for (word, value) in merged.bitmap.iter_mut().zip(bm.bitmap) {
                *word |= value;
            }
        }
        let prefix_len = if dst_ip.is_ipv4() { 32 } else { 128 };
        let prefix = format!("{dst_ip}/{prefix_len}");
        let Ok(lpm_key) = cidr_to_lpm_key(&prefix) else {
            return;
        };
        let mut ebpf = self.ebpf.write().await;
        match ebpf.add_domain_ip_bitmap(&lpm_key, &merged) {
            Ok(()) => debug!(
                "DOMAIN_ROUTING_MAP updated: {} -> {} (rule '{}')",
                dst_ip, domain, rule_name
            ),
            Err(error) => warn!(
                "Failed to update DOMAIN_ROUTING_MAP for {} ({}): {}",
                dst_ip, domain, error
            ),
        }
    }
}

/// Outcome of comparing a connection destination IP against DNS answers for
/// the sniffed domain (`dial_mode: domain` reality check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::control) enum RealityOutcome {
    /// Exact IP present in the same-family answer set.
    ExactMatch,
    /// No answers for the connection's family, but the other family has
    /// records — trust SNI (Happy Eyeballs / Ipv4Only DNS / single-stack auth).
    OtherFamilyOnly,
    /// Same-family answers exist but do not contain the destination, or the
    /// domain did not resolve at all.
    Mismatch,
}

/// Pure reality-check decision (unit-tested). See [`ControlPlane::verify_domain_reality`].
pub(in crate::control) fn domain_reality_outcome(
    expected: std::net::IpAddr,
    ipv4: &[std::net::IpAddr],
    ipv6: &[std::net::IpAddr],
) -> RealityOutcome {
    match expected {
        std::net::IpAddr::V4(v4) => {
            if ipv4.iter().any(|ip| ip == &std::net::IpAddr::V4(v4)) {
                RealityOutcome::ExactMatch
            } else if ipv4.is_empty() && !ipv6.is_empty() {
                RealityOutcome::OtherFamilyOnly
            } else {
                RealityOutcome::Mismatch
            }
        }
        std::net::IpAddr::V6(v6) => {
            if ipv6.iter().any(|ip| ip == &std::net::IpAddr::V6(v6)) {
                RealityOutcome::ExactMatch
            } else if ipv6.is_empty() && !ipv4.is_empty() {
                // The m-team.cc / Cloudflare IPv6 case: client dials AAAA anycast
                // while our resolver (often Ipv4Only) only has A records.
                RealityOutcome::OtherFamilyOnly
            } else {
                RealityOutcome::Mismatch
            }
        }
    }
}

#[cfg(test)]
#[path = "sniffed_domain_routing_tests.rs"]
mod sniffed_domain_routing_tests;
