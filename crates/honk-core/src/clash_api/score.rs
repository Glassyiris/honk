use honk_outbound::alive::IpVersion;
use honk_outbound::group::{
    GroupManager, ScoreComparison, ScoreEvidenceBasis, ScoreEvidenceGaps, ScoreValidationAction,
    ScoreVerificationCounters, ScoreVerificationSnapshot, ScoreVerificationState, SelectionNetwork,
};

pub(super) fn verification(
    group_manager: &GroupManager,
    group: &str,
) -> (Option<String>, serde_json::Value) {
    let tcp = group_manager.score_verification_for_network(group, SelectionNetwork::Tcp);
    let selected = tcp.as_ref().map(|(name, _)| name.clone());
    (
        selected,
        serde_json::json!({
            "objective": "responseQualityWithAvailability",
            "scope": "aggregate",
            "tcp": snapshot(tcp, SelectionNetwork::Tcp),
            "udp": snapshot(group_manager.score_verification_for_network(group, SelectionNetwork::Udp), SelectionNetwork::Udp),
        }),
    )
}

fn snapshot(
    selection: Option<(String, ScoreVerificationSnapshot)>,
    network: SelectionNetwork,
) -> serde_json::Value {
    let (selected, snapshot) = match selection {
        Some((selected, snapshot)) => (Some(selected), Some(snapshot)),
        None => (None, None),
    };
    // No eligible ordinary candidate is not evidence about a final or last resort.
    let snapshot = snapshot.unwrap_or(ScoreVerificationSnapshot {
        state: ScoreVerificationState::Provisional,
        comparison: ScoreComparison::Unconfirmed,
        basis: ScoreEvidenceBasis::None,
        missing: ScoreEvidenceGaps {
            availability: true,
            response: true,
            transfer: true,
        },
        next_action: ScoreValidationAction::None,
        candidate_count: 0,
        compared_count: 0,
        pending_count: 0,
        evidence_age_ms: None,
        valid_for_ms: None,
        network,
        target_family: None,
        health_family: IpVersion::V4,
        target_specific: false,
    });
    serde_json::json!({
        "selected": selected,
        "state": match snapshot.state {
            ScoreVerificationState::Provisional => "provisional",
            ScoreVerificationState::ObservedUsable => "observedUsable",
        },
        "comparison": match snapshot.comparison {
            ScoreComparison::Unconfirmed => "unconfirmed",
            ScoreComparison::Equivalent => "equivalent",
            ScoreComparison::Supported => "supported",
        },
        "basis": match snapshot.basis {
            ScoreEvidenceBasis::None => "none",
            ScoreEvidenceBasis::ConfiguredProbe => "configuredProbe",
            ScoreEvidenceBasis::TargetResponse => "targetResponse",
            ScoreEvidenceBasis::AggregateResponse => "aggregateResponse",
            ScoreEvidenceBasis::Upload => "upload",
            ScoreEvidenceBasis::Download => "download",
        },
        "missing": {
            "availability": snapshot.missing.availability,
            "response": snapshot.missing.response,
            "transfer": snapshot.missing.transfer,
        },
        "nextAction": match snapshot.next_action {
            ScoreValidationAction::None => "none",
            ScoreValidationAction::NextBusinessFlow => "nextBusinessFlow",
            ScoreValidationAction::AwaitTransfer => "awaitTransfer",
            ScoreValidationAction::Backoff => "backoff",
        },
        "coverage": {
            "candidates": snapshot.candidate_count,
            "compared": snapshot.compared_count,
            "pending": snapshot.pending_count,
        },
        "evidenceAgeMs": snapshot.evidence_age_ms,
        "validForMs": snapshot.valid_for_ms,
        "network": match snapshot.network {
            SelectionNetwork::Tcp => "tcp",
            SelectionNetwork::Udp => "udp",
        },
        "targetFamily": snapshot.target_family.map(|family| match family {
            IpVersion::V4 => "ipv4",
            IpVersion::V6 => "ipv6",
        }),
        "healthFamily": match snapshot.health_family {
            IpVersion::V4 => "ipv4",
            IpVersion::V6 => "ipv6",
        },
        "targetSpecific": snapshot.target_specific,
    })
}

pub(super) fn counters(counters: ScoreVerificationCounters) -> serde_json::Value {
    serde_json::json!({
        "provisionalSelections": counters.provisional_selections,
        "usableSelections": counters.usable_selections,
        "validationSelections": counters.validation_selections,
        "confirmations": counters.confirmations,
        "expired": counters.expired,
        "contradicted": counters.contradicted,
        "confirmationMillis": counters.confirmation_millis,
    })
}
