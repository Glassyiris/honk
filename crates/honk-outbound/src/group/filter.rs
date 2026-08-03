//! Candidate liveness filtering: per-node selectability for a probe domain
//! (including the DataUDP/DnsUDP exclusion rules and per-`check_url` probe
//! state) applied to flattened candidates before any policy pick.

use super::*;

impl GroupManager {
    /// Whether a node is selectable for this traffic domain and IP version.
    ///
    /// Data UDP accepts either UDP probe domain after UDP state exists;
    /// unprobed nodes inherit TCP liveness. Other domains use their matching
    /// health state.
    pub fn is_node_selectable_for_domain(
        &self,
        node_id: uuid::Uuid,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> bool {
        let Some(alive) = &self.alive_set else {
            return true;
        };
        if domain == ProbeDomain::DataUdp {
            return if alive.has_udp_state(node_id) {
                alive.is_alive_for(node_id, ProbeDomain::DataUdp, ipver)
                    || alive.is_alive_for(node_id, ProbeDomain::DnsUdp, ipver)
            } else {
                alive.is_alive_for(node_id, ProbeDomain::Tcp, ipver)
            };
        }
        alive.is_alive_for(node_id, domain, ipver)
    }

    /// Keep only candidates whose leaf node is alive for the probe domain.
    /// With no alive set (tests) everything passes.
    ///
    /// When the group has a custom `check_url` (sing-box urltest `url`
    /// option), TCP liveness and ranking come from the per-(node, url)
    /// probe state instead of the global one — a node that cannot reach
    /// the group's own target is excluded here even if it is globally
    /// healthy. UDP domains always use the global state.
    ///
    /// DataUDP aliveness is decided per node: a node is selectable when
    /// DataUDP *or* DnsUDP is alive. A node whose UDP domains are BOTH
    /// explicitly dead is excluded even when its TCP is alive — a TCP-only
    /// node (e.g. an AnyTLS server without UoT) must not keep attracting
    /// UDP flows it cannot carry. The previous set-level
    /// DataUDP → DnsUDP → TCP fallback made such nodes unexcludable.
    /// Nodes with no UDP state at all ([`AliveDialerSet::has_udp_state`]
    /// — never UDP-probed, no UDP traffic reports) instead inherit TCP
    /// liveness, which is what the fallback exists for: setups without
    /// UDP probing keep their previous behaviour.
    pub(super) fn filter_alive_candidates<'a>(
        &self,
        candidates: Vec<Candidate<'a>>,
        domain: ProbeDomain,
        ipver: IpVersion,
        check_url: Option<&str>,
    ) -> Vec<Candidate<'a>> {
        let Some(ref alive) = self.alive_set else {
            return candidates;
        };
        if domain == ProbeDomain::Tcp
            && let Some(url) = check_url
        {
            // Per-URL state is keyed by member TAG (sing-box RealTag
            // semantics): a sub-group is ranked as a unit — the probe
            // dialed its current pick and recorded the result under the
            // sub-group's tag, so a sub-pick change re-evaluates with the
            // tag's state instead of leaking the old leaf's.
            return candidates
                .into_iter()
                .filter(|c| alive.is_alive_for_url(c.tag, url))
                .collect();
        }
        candidates
            .into_iter()
            .filter(|c| self.is_node_selectable_for_domain(c.node.id, domain, ipver))
            .collect()
    }
}
