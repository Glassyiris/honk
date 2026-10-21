use super::*;
use std::collections::HashSet;

pub(super) fn tcp_relay_score_outcome(error: &anyhow::Error) -> crate::group::ScoreOutcome {
    if error.is::<relay::ClientIoError>() {
        crate::group::ScoreOutcome::Cancelled
    } else {
        crate::group::ScoreOutcome::from_error(error)
    }
}

type UnpackedTcpScorePlan = (
    Vec<Node>,
    SelectionPlanMode,
    HashMap<uuid::Uuid, crate::group::ScoreAttempt>,
    HashMap<uuid::Uuid, Vec<String>>,
    HashMap<uuid::Uuid, Vec<String>>,
    IpVersion,
);

pub(super) fn tcp_score_context(
    target: SocketAddr,
    domain: Option<&str>,
    health_family: IpVersion,
) -> crate::group::ScoreSelectionContext {
    let target_family = if target.is_ipv6() {
        IpVersion::V6
    } else {
        IpVersion::V4
    };
    crate::group::ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(target_family),
        health_family,
        target: Some(match domain {
            Some(domain) => crate::group::ScoreTarget::domain(domain, target.port()),
            None => target.into(),
        }),
    }
}

pub(super) fn unpack_tcp_score_plan(
    plan: crate::control::reload::ResolvedScorePlan,
) -> UnpackedTcpScorePlan {
    let mut seen = HashSet::new();
    let mut nodes = Vec::with_capacity(plan.nodes.len());
    let mut feedback = HashMap::new();
    let mut selection_chains = HashMap::new();
    let mut final_owners = HashMap::new();
    for (((node, value), selection_chain), used_final_owners) in plan
        .nodes
        .into_iter()
        .zip(plan.feedback)
        .zip(plan.selection_chains)
        .zip(plan.final_owners)
    {
        if !seen.insert(node.id) {
            continue;
        }
        if let Some(value) = value {
            feedback.insert(node.id, value);
        }
        selection_chains.insert(node.id, selection_chain);
        if !used_final_owners.is_empty() {
            final_owners.insert(node.id, used_final_owners);
        }
        nodes.push(node);
    }
    (
        nodes,
        plan.mode,
        feedback,
        selection_chains,
        final_owners,
        plan.health_family,
    )
}

pub(super) fn timeout_started_score_reporters(
    reporters: &parking_lot::Mutex<Vec<crate::group::ScoreReporter>>,
) {
    for reporter in reporters.lock().iter() {
        reporter.setup_failed(crate::group::ScoreOutcome::Timeout);
    }
}

#[cfg(test)]
pub(super) fn started_score_reporter_count(
    reporters: &parking_lot::Mutex<Vec<crate::group::ScoreReporter>>,
) -> usize {
    reporters.lock().len()
}

pub(super) const COLD_URLTEST_STAGGER: Duration = Duration::from_millis(200);

/// Wait until this candidate's absolute cold-URLTest release offset. The
/// first candidate starts immediately; sleeping candidates have not acquired
/// a dial permit and are dropped with their accepted connection owner.
pub(super) async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
}
