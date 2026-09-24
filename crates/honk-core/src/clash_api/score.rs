use honk_outbound::alive::IpVersion;
use honk_outbound::group::{
    GroupManager, ScoreBudgetCounters, ScoreComparison, ScoreEvidenceBasis, ScoreEvidenceGaps,
    ScoreEvidenceQuestion, ScoreLocalComparison, ScoreValidationAction, ScoreVerificationCounters,
    ScoreVerificationSnapshot, ScoreVerificationState, ScoreWaitReason, SelectionNetwork,
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
        question: ScoreEvidenceQuestion::None,
        wait_reason: ScoreWaitReason::None,
        local_comparison: ScoreLocalComparison::default(),
        candidate_count: 0,
        evaluated_count: 0,
        compared_count: 0,
        pending_count: 0,
        blockers: Default::default(),
        target_limited: false,
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
        "comparison": comparison_name(snapshot.comparison),
        "basis": basis_name(snapshot.basis),
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
        "question": match snapshot.question {
            ScoreEvidenceQuestion::None => "none",
            ScoreEvidenceQuestion::Availability => "availability",
            ScoreEvidenceQuestion::Response => "response",
            ScoreEvidenceQuestion::Qualification => "qualification",
            ScoreEvidenceQuestion::Recovery => "recovery",
            ScoreEvidenceQuestion::Transfer => "transfer",
        },
        "waitReason": match snapshot.wait_reason {
            ScoreWaitReason::None => "none",
            ScoreWaitReason::Budget => "budget",
            ScoreWaitReason::ComparableTraffic => "comparableTraffic",
            ScoreWaitReason::InFlight => "inFlight",
            ScoreWaitReason::Transfer => "transfer",
            ScoreWaitReason::Backoff => "backoff",
        },
        "localComparison": local_comparison(snapshot.local_comparison),
        "coverage": {
            "scope": if snapshot.evaluated_count < snapshot.candidate_count { "bounded" } else { "all" },
            "candidates": snapshot.candidate_count,
            "evaluated": snapshot.evaluated_count,
            "unevaluated": snapshot.candidate_count - snapshot.evaluated_count,
            "compared": snapshot.compared_count,
            "pending": snapshot.pending_count,
            "targetLimited": snapshot.target_limited,
            "excluded": snapshot.blockers.excluded,
        },
        "blockers": {
            "recovery": snapshot.blockers.recovery,
            "backoff": snapshot.blockers.backoff,
            "qualification": snapshot.blockers.qualification,
            "availability": snapshot.blockers.availability,
            "responseMissing": snapshot.blockers.response_missing,
            "responseUnpaired": snapshot.blockers.response_unpaired,
            "responseMisaligned": snapshot.blockers.response_misaligned,
            "probeScope": snapshot.blockers.probe_scope,
            "responseDegraded": snapshot.blockers.response_degraded,
            "nodeFailure": snapshot.blockers.node_failure,
            "targetFailure": snapshot.blockers.target_failure,
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

fn local_comparison(value: ScoreLocalComparison) -> serde_json::Value {
    serde_json::json!({
        "scope": "activeChallengers",
        "comparison": comparison_name(value.comparison),
        "basis": basis_name(value.basis),
        "comparedCandidates": value.compared_candidates,
        "reporters": value.reporter_count,
        "spanMs": value.span_ms,
        "evidenceAgeMs": value.evidence_age_ms,
        "validForMs": value.valid_for_ms,
        "dispersionPpm": value.dispersion_ppm,
        "uploadKnown": value.upload_known,
        "downloadKnown": value.download_known,
        "directionalTradeoff": value.directional_tradeoff,
    })
}

fn comparison_name(comparison: ScoreComparison) -> &'static str {
    match comparison {
        ScoreComparison::Unconfirmed => "unconfirmed",
        ScoreComparison::Equivalent => "equivalent",
        ScoreComparison::Supported => "supported",
    }
}

fn basis_name(basis: ScoreEvidenceBasis) -> &'static str {
    match basis {
        ScoreEvidenceBasis::None => "none",
        ScoreEvidenceBasis::ConfiguredProbe => "configuredProbe",
        ScoreEvidenceBasis::TargetResponse => "targetResponse",
        ScoreEvidenceBasis::CommonTargets => "commonTargets",
        ScoreEvidenceBasis::Upload => "upload",
        ScoreEvidenceBasis::Download => "download",
    }
}

pub(super) fn budget(value: ScoreBudgetCounters) -> serde_json::Value {
    serde_json::json!({
        "businessStarts": value.business_starts,
        "sources": { "cold": value.cold_trial_starts, "periodic": value.periodic_trial_starts, "recovery": value.recovery_starts },
        "trialStarts": value.trial_starts,
        "reserved": value.reserved,
        "spent": value.spent,
        "budgetBlocked": value.budget_blocked,
        "inFlightBlocked": value.in_flight_blocked,
        "refunded": value.refunded,
        "expired": value.expired,
        "coldAllowance": value.cold_allowance,
        "coldAvailable": value.cold_available,
        "earnedAvailable": value.earned_available,
        "earningPeriod": value.earning_period,
        "scopes": value.scopes,
        "trialSuccess": value.trial_success,
        "trialFailure": value.trial_failure,
        "trialCancelled": value.trial_cancelled,
        "trialSetupHistogram": value.trial_setup_histogram,
        "trialSetupMillis": value.trial_setup_millis,
        "trialElapsedMillis": value.trial_elapsed_millis,
    })
}
