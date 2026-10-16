//! One backend-exclusive retirement protocol for every tuple-map deletion.
use super::*;
use crate::ebpf::retirement::{
    conn_matches, handoff_matches, redirect_matches, request_matches, tuple_matches,
};
use aya::maps::ArrayOfMaps;
use honk_ebpf_common::conn::TcpState;
use honk_ebpf_common::conn::{
    MAX_CONN_STATE_NUM, RetirementFence, TCP_CONN_STATE_CLOSING_TIMEOUT_NS,
    TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, UDP_CONN_STATE_TIMEOUT_NS,
};
use honk_ebpf_common::redirect_need::TcpSocketBinding;

const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
const IPPROTO_UDP: u8 = libc::IPPROTO_UDP as u8;

#[cfg(test)]
#[derive(Default)]
pub(super) struct RetirementFaults {
    pub(super) acquire: Option<usize>,
    pub(super) barrier: bool,
    pub(super) release: Option<usize>,
    pub(super) delete: Option<usize>,
    pub(super) quiesce_after_scan: Option<fn(&mut RealEbpfBackend) -> anyhow::Result<()>>,
}

#[cfg(test)]
pub(super) fn inject_indexed_fault(index: &mut Option<usize>, kind: &str) -> anyhow::Result<()> {
    if let Some(remaining) = index {
        if *remaining == 0 {
            *index = None;
            anyhow::bail!("injected retirement {kind} failure");
        }
        *remaining -= 1;
    }
    Ok(())
}

pub(super) fn validate_flow_lifetime_layout(bpf: &Ebpf) -> anyhow::Result<()> {
    use aya_obj::generated::bpf_map_type::*;
    for (name, type_, key, value, count, flags) in [
        (
            "CONN_STATE_MAP",
            BPF_MAP_TYPE_HASH,
            40,
            64,
            MAX_CONN_STATE_NUM,
            1,
        ),
        ("REDIRECT_TRACK", BPF_MAP_TYPE_HASH, 40, 40, 65536, 1),
        ("ROUTING_HANDOFF_MAP", BPF_MAP_TYPE_HASH, 40, 72, 65536, 1),
        ("RETIRE_ACTIVE", BPF_MAP_TYPE_ARRAY, 4, 4, 1, 0),
        ("RETIRE_FENCE", BPF_MAP_TYPE_HASH, 40, 16, 65536, 1),
        ("FLOW_INCARNATION_SEQUENCE", BPF_MAP_TYPE_ARRAY, 4, 16, 1, 0),
        ("RETIRE_GRACE_ROOT", BPF_MAP_TYPE_ARRAY_OF_MAPS, 4, 4, 1, 0),
        ("TCP_REQUEST_BINDINGS", BPF_MAP_TYPE_HASH, 16, 120, 65536, 1),
        ("TCP_PUBLISHING", BPF_MAP_TYPE_HASH, 40, 8, 65536, 1),
        ("TCP_SOCKET_BINDING", BPF_MAP_TYPE_SK_STORAGE, 4, 120, 0, 1),
    ] {
        syscall::validate_map_layout(bpf, name, type_, key, value, count, flags)?;
    }
    Ok(())
}

pub(super) fn init_retirement_grace(bpf: &mut Ebpf) -> anyhow::Result<AyaArray<AyaMapData, u32>> {
    let inner = AyaArray::create(1, 0)?;
    let root = bpf
        .map_mut("RETIRE_GRACE_ROOT")
        .ok_or_else(|| anyhow::anyhow!("RETIRE_GRACE_ROOT unavailable"))?;
    ArrayOfMaps::<_, AyaArray<AyaMapData, u32>>::try_from(root)?.set(0, &inner, 0)?;
    Ok(inner)
}

fn combine_error(original: &mut Option<anyhow::Error>, error: anyhow::Error) {
    *original = Some(match original.take() {
        Some(previous) => previous.context(format!("additional retirement failure: {error:#}")),
        None => error,
    });
}

impl RealEbpfBackend {
    pub(super) fn grace_barrier(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        #[cfg(test)]
        if std::mem::take(&mut self.retirement_faults.barrier) {
            anyhow::bail!("injected retirement barrier failure");
        }
        let bpf = self
            .bpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF backend closed"))?;
        let root = bpf
            .map_mut("RETIRE_GRACE_ROOT")
            .ok_or_else(|| anyhow::anyhow!("RETIRE_GRACE_ROOT unavailable"))?;
        // Linux map-in-map replacement synchronously waits for pre-update BPF
        // readers even when reinstalling the same inner FD. Never route through
        // policy publication: this private map is owned for this backend lifetime.
        ArrayOfMaps::<_, AyaArray<AyaMapData, u32>>::try_from(root)?.set(
            0,
            &self.retirement_grace_inner,
            0,
        )?;
        Ok(())
    }

    pub(super) fn with_retirement_fences<T>(
        &mut self,
        keys: &[(TuplesKey, u32)],
        operation: impl FnOnce(&mut Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        anyhow::ensure!(
            keys.len() <= RETIRE_BATCH_CAPACITY,
            "retirement batch exceeds capacity"
        );
        anyhow::ensure!(
            keys.iter().all(|(key, _)| key.padding == [0; 3]),
            "noncanonical retirement tuple"
        );
        let Some(owner) = self.retirement_owner.checked_add(1) else {
            self.retirement_failed = true;
            anyhow::bail!("retirement operation owner exhausted");
        };
        self.retirement_owner = owner;
        // Backend W serializes operation ownership; fixed storage avoids per-key allocation.
        let mut acquired = [None; RETIRE_BATCH_CAPACITY];
        let mut count = 0;
        let mut failure = None;
        let mut value = None;
        let mut unresolved = false;
        self.array_set("RETIRE_ACTIVE", 0, &1u32)?;
        for (key, token) in keys {
            if acquired[..count]
                .iter()
                .flatten()
                .any(|previous| tuple_matches(previous, key))
            {
                continue;
            }
            let mut canonical = *key;
            canonical.padding = [0; 3];
            let fence = RetirementFence {
                owner,
                decision_token: *token,
                padding: 0,
            };
            #[cfg(test)]
            let acquisition = inject_indexed_fault(&mut self.retirement_faults.acquire, "acquire")
                .and_then(|()| self.hash_insert_noexist(RETIRE_FENCE_MAP, &canonical, &fence));
            #[cfg(not(test))]
            let acquisition = self.hash_insert_noexist(RETIRE_FENCE_MAP, &canonical, &fence);
            match acquisition {
                Ok(()) => {
                    acquired[count] = Some(canonical);
                    count += 1;
                }
                Err(error) => {
                    failure = Some(error);
                    match self.hash_lookup::<_, RetirementFence>(RETIRE_FENCE_MAP, &canonical) {
                        Ok(None) => {}
                        Ok(Some(_)) => unresolved = true,
                        Err(error) => {
                            unresolved = true;
                            combine_error(&mut failure, error);
                        }
                    }
                    break;
                }
            }
        }
        if failure.is_none() {
            match self.grace_barrier().and_then(|()| {
                for key in acquired[..count].iter().flatten() {
                    let current = self.hash_lookup::<_, RetirementFence>(RETIRE_FENCE_MAP, key)?;
                    anyhow::ensure!(
                        current.is_some_and(|fence| fence.owner == owner),
                        "retirement fence owner {owner} changed before mutation"
                    );
                }
                operation(self)
            }) {
                Ok(result) => value = Some(result),
                Err(error) => failure = Some(error),
            }
        }
        for key in acquired[..count].iter().flatten() {
            let release = (|| {
                #[cfg(test)]
                inject_indexed_fault(&mut self.retirement_faults.release, "release")?;
                let current = self.hash_lookup::<_, RetirementFence>(RETIRE_FENCE_MAP, key)?;
                anyhow::ensure!(
                    current.is_some_and(|fence| fence.owner == owner),
                    "retirement fence owner {owner} disappeared or changed"
                );
                anyhow::ensure!(
                    self.hash_remove_present::<_, RetirementFence>(RETIRE_FENCE_MAP, key)?,
                    "retirement fence owner {owner} disappeared during release"
                );
                Ok(())
            })();
            if let Err(error) = release {
                unresolved = true;
                combine_error(&mut failure, error);
            }
        }
        if unresolved {
            self.retirement_failed = true;
        } else if let Err(error) = self.array_set("RETIRE_ACTIVE", 0, &0u32) {
            self.retirement_failed = true;
            combine_error(&mut failure, error);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(value.expect("successful retirement operation produced a result")),
        }
    }

    pub(super) fn retire_flows(
        &mut self,
        requests: &[RetireRequest<'_>],
        outcomes: &mut [Option<UdpDecisionCommitResult>],
    ) -> Result<RetireCounts, RetireError> {
        outcomes.fill(None);
        let mut counts = RetireCounts::default();
        let run = (|| {
            anyhow::ensure!(
                requests.len() == outcomes.len() && requests.len() <= RETIRE_BATCH_CAPACITY,
                "retirement input/output length mismatch or capacity exceeded"
            );
            anyhow::ensure!(
                !self.retirement_failed,
                "retirement ownership is unresolved"
            );
            if requests.is_empty() {
                return Ok(());
            }
            let mut keys = [(TuplesKey::default(), 0); RETIRE_BATCH_CAPACITY];
            for (index, request) in requests.iter().enumerate() {
                anyhow::ensure!(
                    request.key.padding == [0; 3]
                        && matches!(request.key.l4proto, IPPROTO_TCP | IPPROTO_UDP),
                    "noncanonical retirement tuple"
                );
                let token = match request.kind {
                    RetireKind::Tcp { incarnation } => {
                        anyhow::ensure!(
                            request.key.l4proto == IPPROTO_TCP && incarnation != 0,
                            "invalid TCP retirement owner"
                        );
                        0
                    }
                    RetireKind::Udp {
                        token, incarnation, ..
                    } => {
                        anyhow::ensure!(
                            request.key.l4proto == IPPROTO_UDP
                                && incarnation != Some(0)
                                && (token != 0 || incarnation.is_some()),
                            "invalid UDP retirement owner"
                        );
                        token
                    }
                    RetireKind::ExpiredConn { expected, .. } => expected.decision_token,
                    RetireKind::ExpiredRedirect { expected, .. } => expected.decision_token,
                    RetireKind::ExpiredHandoff { expected, .. } => expected.result.decision_token,
                    RetireKind::ExpiredRequest { expected, .. } => {
                        anyhow::ensure!(
                            tuple_matches(&request.key, &expected.tuples),
                            "request proof tuple mismatch"
                        );
                        expected.handoff.result.decision_token
                    }
                    RetireKind::ExpiryHint { incarnation, .. } => {
                        anyhow::ensure!(incarnation != 0, "invalid expiry incarnation");
                        0
                    }
                };
                keys[index] = (request.key, token);
            }
            self.with_retirement_fences(&keys[..requests.len()], |backend| {
                for (request, outcome) in requests.iter().zip(outcomes) {
                    *outcome = Some(backend.retire_one(request, &mut counts)?);
                }
                Ok(())
            })
        })();
        match run {
            Ok(()) => Ok(counts),
            Err(source) => Err(RetireError { counts, source }),
        }
    }

    fn retire_one(
        &mut self,
        request: &RetireRequest<'_>,
        counts: &mut RetireCounts,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        use UdpDecisionCommitResult::*;
        let key = &request.key;
        let track_key = RedirectTuple::from_tuples(key);
        match request.kind {
            RetireKind::ExpiredRequest {
                request,
                expected,
                expired_before_ns,
            } => {
                let Some(current) =
                    self.hash_lookup::<_, TcpSocketBinding>("TCP_REQUEST_BINDINGS", request)?
                else {
                    return Ok(Missing);
                };
                if !request_matches(&current, expected, expired_before_ns) {
                    return Ok(Superseded);
                }
                counts.request +=
                    u64::from(self.hash_remove_present::<_, TcpSocketBinding>(
                        "TCP_REQUEST_BINDINGS",
                        request,
                    )?);
                return Ok(Applied);
            }
            RetireKind::ExpiredRedirect {
                expected,
                expired_before_ns,
            } => {
                let Some(current) =
                    self.hash_lookup::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?
                else {
                    return Ok(Missing);
                };
                if !redirect_matches(&current, expected, expired_before_ns) {
                    return Ok(Superseded);
                }
                counts.redirect += u64::from(
                    self.hash_remove_present::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?,
                );
                return Ok(Applied);
            }
            RetireKind::ExpiredHandoff {
                expected,
                expired_before_ns,
            } => {
                let Some(current) =
                    self.hash_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?
                else {
                    return Ok(Missing);
                };
                if !handoff_matches(&current, expected, expired_before_ns) {
                    return Ok(Superseded);
                }
                counts.handoff += u64::from(
                    self.hash_remove_present::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?,
                );
                return Ok(Applied);
            }
            _ => {}
        }
        if let RetireKind::ExpiryHint {
            incarnation,
            now_ns,
        } = request.kind
        {
            let current = self.hash_lookup::<_, ConnState>("CONN_STATE_MAP", key)?;
            if current.is_some_and(|state| state.incarnation != incarnation) {
                return Ok(Superseded);
            }
            let expired = current.is_some_and(|state| {
                let timeout = if key.l4proto == IPPROTO_UDP {
                    UDP_CONN_STATE_TIMEOUT_NS
                } else if state.state == TcpState::TcpStateClosing as u8 {
                    TCP_CONN_STATE_CLOSING_TIMEOUT_NS
                } else {
                    TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
                };
                now_ns.saturating_sub(state.last_seen_ns) > timeout
            });
            if !expired {
                let handoff =
                    self.hash_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
                let track = self.hash_lookup::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
                if let Some(state) = current {
                    if handoff.is_some_and(|entry| {
                        entry.incarnation == incarnation
                            && entry.result.decision_token != state.decision_token
                    }) || track.is_some_and(|entry| {
                        entry.incarnation == incarnation
                            && entry.decision_token != state.decision_token
                    }) {
                        return Ok(TokenMismatch);
                    }
                } else if let (Some(handoff), Some(track)) = (handoff, track)
                    && handoff.incarnation == incarnation
                    && track.incarnation == incarnation
                    && handoff.result.decision_token != track.decision_token
                {
                    return Ok(TokenMismatch);
                }
                let mut removed = false;
                if handoff.is_some_and(|entry| {
                    entry.incarnation == incarnation
                        && now_ns.saturating_sub(entry.last_seen_ns) > 30_000_000_000
                }) {
                    let deleted = self.hash_remove_present::<_, RoutingHandoffEntry>(
                        "ROUTING_HANDOFF_MAP",
                        key,
                    )?;
                    counts.handoff += u64::from(deleted);
                    removed |= deleted;
                }
                if track.is_some_and(|entry| {
                    entry.incarnation == incarnation
                        && now_ns.saturating_sub(entry.last_seen_ns) > 120_000_000_000
                }) {
                    let deleted =
                        self.hash_remove_present::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
                    counts.redirect += u64::from(deleted);
                    removed |= deleted;
                }
                return Ok(if removed {
                    Applied
                } else if current.is_none() && handoff.is_none() && track.is_none() {
                    Missing
                } else {
                    StateMismatch
                });
            }
        }
        let Some(state) = self.hash_lookup::<_, ConnState>("CONN_STATE_MAP", key)? else {
            return Ok(Missing);
        };
        let remove_aux = match request.kind {
            RetireKind::Tcp { incarnation } => {
                if state.incarnation != incarnation {
                    return Ok(Superseded);
                }
                true
            }
            RetireKind::Udp {
                token,
                incarnation,
                pending_only,
            } => {
                if state.decision_token != token
                    || incarnation.is_some_and(|id| id != state.incarnation)
                {
                    return Ok(if pending_only {
                        TokenMismatch
                    } else {
                        Superseded
                    });
                }
                anyhow::ensure!(state.incarnation != 0, "UDP conn has no lifetime identity");
                if pending_only {
                    if state.state != UdpDecisionState::Preparing as u8
                        && state.state != UdpDecisionState::Pending as u8
                    {
                        return Ok(StateMismatch);
                    }
                } else if token != 0 {
                    if !udp_state_is_userspace_owned(state.state) {
                        return Ok(StateMismatch);
                    }
                } else if !udp_state_is_legacy_userspace_owned(&state) {
                    return Ok(Superseded);
                }
                token != 0
                    || pending_only
                    || unsafe { state.meta.raw } & ROUTING_META_FLAG_WAN_USERSPACE != 0
            }
            RetireKind::ExpiredConn {
                expected,
                expired_before_ns,
            } => {
                if !conn_matches(&state, expected, expired_before_ns) {
                    return Ok(Superseded);
                }
                false
            }
            RetireKind::ExpiryHint {
                incarnation,
                now_ns,
            } => {
                if state.incarnation != incarnation {
                    return Ok(Superseded);
                }
                let timeout = if key.l4proto == IPPROTO_UDP {
                    UDP_CONN_STATE_TIMEOUT_NS
                } else if state.state == TcpState::TcpStateClosing as u8 {
                    TCP_CONN_STATE_CLOSING_TIMEOUT_NS
                } else {
                    TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
                };
                if now_ns.saturating_sub(state.last_seen_ns) <= timeout {
                    return Ok(StateMismatch);
                }
                true
            }
            _ => unreachable!("auxiliary expiry handled above"),
        };
        if remove_aux {
            let handoff = self.hash_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
            let track = self.hash_lookup::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
            if handoff.is_some_and(|entry| {
                entry.incarnation != state.incarnation
                    || entry.result.decision_token != state.decision_token
            }) || track.is_some_and(|entry| {
                entry.incarnation != state.incarnation
                    || entry.decision_token != state.decision_token
            }) {
                return Ok(TokenMismatch);
            }
            if handoff.is_some() {
                counts.handoff += u64::from(
                    self.hash_remove_present::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?,
                );
            }
            if track.is_some() {
                counts.redirect += u64::from(
                    self.hash_remove_present::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?,
                );
            }
        }
        let removed = self.hash_remove_present::<_, ConnState>("CONN_STATE_MAP", key)?;
        counts.conn += u64::from(removed);
        Ok(if removed { Applied } else { Missing })
    }

    pub(super) fn commit_udp_fenced(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        anyhow::ensure!(
            !self.retirement_failed,
            "retirement ownership is unresolved"
        );
        validate_udp_decision_transition(transition)?;
        if token == 0 {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let Some(captured) = self.hash_lookup::<_, ConnState>("CONN_STATE_MAP", key)? else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        self.with_retirement_fences(&[(*key, token)], |backend| {
            let Some(mut state) = backend.hash_lookup::<_, ConnState>("CONN_STATE_MAP", key)?
            else {
                return Ok(UdpDecisionCommitResult::Missing);
            };
            if state.decision_token != token || state.incarnation != captured.incarnation {
                return Ok(UdpDecisionCommitResult::TokenMismatch);
            }
            anyhow::ensure!(
                state.incarnation != 0,
                "UDP commit has no lifetime identity"
            );
            if let Err(result) = apply_udp_decision_transition(&mut state, transition) {
                return Ok(result);
            }
            let handoff =
                backend.hash_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
            let track_key = RedirectTuple::from_tuples(key);
            let track = backend.hash_lookup::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
            if handoff.is_some_and(|entry| {
                entry.result.decision_token != token || entry.incarnation != state.incarnation
            }) || track.is_some_and(|entry| {
                entry.decision_token != token || entry.incarnation != state.incarnation
            }) {
                return Ok(UdpDecisionCommitResult::TokenMismatch);
            }
            let initial = !matches!(transition, UdpDecisionTransition::ActivateDirect(_));
            if initial && (handoff.is_none() || track.is_none()) {
                return Ok(UdpDecisionCommitResult::Missing);
            }
            if handoff.is_some() {
                backend.hash_remove::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?;
            }
            match transition {
                UdpDecisionTransition::ActivateProxy(outbound, _) => {
                    let mut track = track.expect("proxy track validated");
                    track.outbound = outbound;
                    backend.hash_insert("REDIRECT_TRACK", &track_key, &track)?;
                }
                _ => {
                    if track.is_some() {
                        backend.hash_remove::<_, RedirectEntry>("REDIRECT_TRACK", &track_key)?;
                    }
                }
            }
            backend.hash_insert("CONN_STATE_MAP", key, &state)?;
            Ok(UdpDecisionCommitResult::Applied)
        })
    }
}
