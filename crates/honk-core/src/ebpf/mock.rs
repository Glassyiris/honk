//! Mock eBPF backend for testing.
//!
//! This backend implements the `EbpfBackend` trait using in-memory
//! data structures instead of real kernel eBPF. All operations use
//! HashMap storage.

#[cfg(test)]
use super::RetireKind;
#[cfg(test)]
use super::TcpSocketOwnership;
#[cfg(test)]
use super::retirement::retire_fixture;
use super::retirement::{
    Owners, RedirectEffect, account_retirement, plan_retirement, plan_udp_commit,
    release_request_count, retire_staged_udp,
};
#[cfg(test)]
use super::{DatapathFlagsWriteOrigin, DatapathFlagsWriteTrace, ProjectionMapOperation};
use super::{
    EbpfBackend, RoutingPushPhase, UdpDecisionCommitResult, UdpDecisionSequenceStatus,
    UdpDecisionTransition, validate_udp_decision_transition,
};
use super::{
    FlowExpiryHint, RETIRE_BATCH_CAPACITY, RetireCounts, RetireError, RetireOutcome, RetireRequest,
    udp_state_is_staged,
};
use async_trait::async_trait;
use honk_ebpf_common::*;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockRoutingSnapshot {
    pub active_slot: u32,
    pub descriptor: RoutingPolicyDescriptor,
    pub plan_fingerprint: [u8; 32],
    pub rule_count: usize,
    pub destination_v4: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub destination_v6: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub source_v4: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub source_v6: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub mac: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
    pub domain: Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockRoutingPublicationWrite {
    FactMaps(u32),
    Program(u32),
    Attach(u32),
    Root(u32),
}

#[derive(Debug, Clone)]
struct MockRoutingGeneration {
    fingerprint: [u8; 32],
    rule_count: usize,
    facts: crate::control::routing_matcher::RoutingFactMaps,
    domain: HashMap<[u32; 4], DomainRouting>,
}

/// In-memory transactional routing backend used by control-plane tests.
#[derive(Debug, Default)]
pub struct MockEbpfBackend {
    /// Only the generation selected by the stable root remains resident.
    routing_generation: Option<MockRoutingGeneration>,
    active_slot: u32,
    descriptor: RoutingPolicyDescriptor,
    next_generation: u64,
    next_domain_map_id: u32,
    next_trace_policy: u32,
    #[cfg(feature = "native-api")]
    trace_dictionaries: crate::observe::flows::kernel::KernelTraceDictionaries,
    pub route_witnesses: HashMap<u32, KernelRouteWitness>,
    next_trace_id: u32,
    /// TCP connection states (TuplesKey → ConnState)
    pub tcp_conn_states: HashMap<[u8; 40], ConnState>,
    /// UDP connection states (TuplesKey → ConnState)
    pub udp_conn_states: HashMap<[u8; 40], ConnState>,
    /// Redirect tracking (full directional `RedirectTuple` → `RedirectEntry`).
    pub redirect_tracks: HashMap<[u8; 40], RedirectEntry>,
    /// Routing handoff table (TuplesKey → RoutingHandoffEntry).
    pub routing_handoffs: parking_lot::Mutex<HashMap<[u8; 40], RoutingHandoffEntry>>,
    /// Explicit request-proof fixtures, not simulated kernel socket ownership.
    pub tcp_request_bindings: HashMap<(u64, u64), TcpSocketBinding>,
    /// Tuple fences retained by model fixtures for allocator conflict checks.
    retire_fences: HashMap<[u8; 40], RetirementFence>,
    #[cfg(test)]
    pub retire_fault_after: Option<usize>,
    /// Outbound alive bitmap: (outbound*6 + domain*2 + ipver) → 0|1
    pub outbound_alive: HashMap<u32, u32>,
    /// BPF statistics overflow counters
    pub bpf_stats: HashMap<u32, u64>,
    /// Whether TC entry points may redirect traffic into the control plane.
    pub datapath_ready: bool,
    pub listener_sockets_published: bool,
    listener_socket_slots: HashMap<u32, std::os::fd::RawFd>,
    #[cfg(test)]
    pub listener_clear_fault_at: Option<u32>,
    /// Every mode-policy write, shared so tests can inspect boxed backends.
    pub datapath_flags_writes: std::sync::Arc<parking_lot::Mutex<Vec<u32>>>,
    pub detach_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub dynamic_attach_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(test)]
    pub dynamic_attach_fault: bool,
    pub dynamic_forget_calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub routing_publication_order: Vec<MockRoutingPublicationWrite>,
    #[cfg(feature = "reload-bench-counters")]
    routing_map_writes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(feature = "reload-bench-counters")]
    outbound_alive_writes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Persistent allocator state; cleanup intentionally leaves this intact.
    pub udp_decision_sequence_next: u32,
    pub udp_decision_sequence_generation: u32,
    routing_fault: Option<(RoutingPushPhase, usize)>,
    #[cfg(test)]
    projection_fault: Option<(ProjectionMapOperation, usize, bool)>,
    #[cfg(test)]
    projection_writes: Vec<ProjectionMapOperation>,
    #[cfg(test)]
    domain_bitmap_add_faults: usize,
    #[cfg(test)]
    fail_next_quiesce: bool,
    #[cfg(test)]
    datapath_flags_fault_nth: Option<usize>,
    #[cfg(test)]
    datapath_flags_writes_after_arm: usize,
    #[cfg(test)]
    datapath_flags_write_origin: DatapathFlagsWriteOrigin,
    #[cfg(test)]
    datapath_flags_write_trace: Vec<DatapathFlagsWriteTrace>,
    #[cfg(test)]
    pub datapath_observation_fixture: Option<super::DatapathObservation>,
    #[cfg(test)]
    pub pname_support: super::PnameSupport,
}

impl MockEbpfBackend {
    /// Create a new mock backend.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn capture_route_witness(&mut self, mut witness: KernelRouteWitness) -> u32 {
        if witness.output.flags & ROUTE_TRACE_ENABLED == 0 {
            return 0;
        }
        if self.next_trace_id >= ROUTE_TRACE_LOST - 1 {
            return ROUTE_TRACE_LOST;
        }
        self.next_trace_id += 1;
        let id = self.next_trace_id;
        witness.capture_id = id;
        if self.route_witnesses.len() >= ROUTE_TRACE_CAPACITY as usize
            && let Some(oldest) = self.route_witnesses.keys().min().copied()
        {
            self.route_witnesses.remove(&oldest);
        }
        self.route_witnesses.insert(id, witness);
        id
    }

    #[cfg(feature = "reload-bench-counters")]
    pub fn routing_map_write_counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        std::sync::Arc::clone(&self.routing_map_writes)
    }

    #[cfg(feature = "reload-bench-counters")]
    pub fn outbound_alive_write_counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        std::sync::Arc::clone(&self.outbound_alive_writes)
    }

    #[inline]
    fn count_routing_writes(&self, count: u64) {
        #[cfg(feature = "reload-bench-counters")]
        self.routing_map_writes
            .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(feature = "reload-bench-counters"))]
        let _ = count;
    }

    #[inline]
    fn count_outbound_alive_write(&self) {
        #[cfg(feature = "reload-bench-counters")]
        self.outbound_alive_writes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn seed_staged_udp_flow(&mut self, key: &TuplesKey, state: ConnState) {
        let token = state.decision_token;
        assert_ne!(token, 0);
        assert_eq!(state.state, UdpDecisionState::Pending as u8);
        self.udp_conn_state_store(key, &state).unwrap();
        self.routing_handoffs.lock().insert(
            Self::tuples_key_bytes(key),
            RoutingHandoffEntry {
                result: RoutingResult {
                    decision_token: token,
                    ..Default::default()
                },
                routing_generation: 0,
                incarnation: state.incarnation,
                ..Default::default()
            },
        );
        self.redirect_track_store(
            &RedirectTuple::from_tuples(key),
            &RedirectEntry {
                decision_token: token,
                outbound: OutboundIndex::UserBase as u8,
                incarnation: state.incarnation,
                ..Default::default()
            },
        )
        .unwrap();
    }

    fn conn_states(&self, proto: u8) -> &HashMap<[u8; 40], ConnState> {
        if proto == libc::IPPROTO_TCP as u8 {
            &self.tcp_conn_states
        } else {
            &self.udp_conn_states
        }
    }

    fn conn_states_mut(&mut self, proto: u8) -> &mut HashMap<[u8; 40], ConnState> {
        if proto == libc::IPPROTO_TCP as u8 {
            &mut self.tcp_conn_states
        } else {
            &mut self.udp_conn_states
        }
    }

    // Explicit model fixtures may use zero identities that native backends reject, and
    // exclusive access stands in for the kernel fence and grace barrier.
    fn retire_model_request(
        &mut self,
        request: &RetireRequest<'_>,
        counts: &mut RetireCounts,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        let raw = Self::tuples_key_bytes(&request.key);
        let track_raw = Self::redirect_tuple_bytes(&RedirectTuple::from_tuples(&request.key));
        let reads = request.kind.owner_reads();
        let conn = reads
            .conn
            .then(|| self.conn_states(request.key.l4proto).get(&raw).copied())
            .flatten();
        let handoff = reads
            .handoff
            .then(|| self.routing_handoffs.lock().get(&raw).copied())
            .flatten();
        let redirect = reads
            .redirect
            .then(|| self.redirect_tracks.get(&track_raw).copied())
            .flatten();
        let binding = reads.request.and_then(|proof| {
            self.tcp_request_bindings
                .get(&(proof.address, proof.cookie))
                .copied()
        });
        let owners = Owners {
            conn: conn.as_ref(),
            handoff: handoff.as_ref(),
            redirect: redirect.as_ref(),
            request: binding.as_ref(),
        };
        let plan = match plan_retirement(request, &owners) {
            Ok(plan) => plan,
            Err(result) => return Ok(result),
        };
        let before = *counts;
        if plan.handoff {
            counts.handoff += u64::from(self.routing_handoffs.get_mut().remove(&raw).is_some());
        }
        if plan.redirect {
            counts.redirect += u64::from(self.redirect_tracks.remove(&track_raw).is_some());
        }
        if let (Some(incarnation), Some(proof)) = (plan.request, reads.request)
            && self
                .tcp_request_bindings
                .remove(&(proof.address, proof.cookie))
                .is_some()
        {
            counts.request += 1;
            if let Some(state) = self.tcp_conn_states.get_mut(&raw) {
                release_request_count(state, incarnation)?;
            }
        }
        if plan.conn {
            counts.conn += u64::from(
                self.conn_states_mut(request.key.l4proto)
                    .remove(&raw)
                    .is_some(),
            );
        }
        Ok(plan.outcome((*counts).since(before)))
    }

    fn retire_model_batch(
        &mut self,
        requests: &[RetireRequest<'_>],
        outcomes: &mut [RetireOutcome],
        counts: &mut RetireCounts,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            requests.len() == outcomes.len() && requests.len() <= RETIRE_BATCH_CAPACITY,
            "invalid retirement batch length"
        );
        anyhow::ensure!(
            self.retire_fences.is_empty(),
            "unresolved model retirement fences"
        );
        for (index, (request, outcome)) in requests.iter().zip(outcomes).enumerate() {
            #[cfg(test)]
            if self.retire_fault_after == Some(index) {
                self.retire_fault_after = None;
                anyhow::bail!("injected retirement failure");
            }
            #[cfg(not(test))]
            let _ = index;
            *outcome = self.retire_model_request(request, counts)?.into();
        }
        Ok(())
    }

    pub fn fail_next_routing_phase(&mut self, phase: RoutingPushPhase) {
        self.routing_fault = Some((phase, 1));
    }

    fn fact_snapshot(
        entries: &[(LpmKey, DomainRouting)],
    ) -> Vec<([u8; 20], [u32; ROUTING_BITMAP_WORDS])> {
        let mut result = entries
            .iter()
            .map(|(key, value)| (Self::lpm_key_bytes(key), value.bitmap))
            .collect::<Vec<_>>();
        result.sort_by_key(|(key, _)| *key);
        result
    }

    pub fn routing_snapshot(&self) -> MockRoutingSnapshot {
        let generation = self.routing_generation.as_ref();
        let (fingerprint, rule_count, facts, mut domain) =
            generation.map_or(([0; 32], 0, None, Vec::new()), |generation| {
                let domain = generation
                    .domain
                    .iter()
                    .map(|(key, value)| {
                        let key = LpmKey {
                            prefix_len: 128,
                            data: *key,
                        };
                        (Self::lpm_key_bytes(&key), value.bitmap)
                    })
                    .collect::<Vec<_>>();
                (
                    generation.fingerprint,
                    generation.rule_count,
                    Some(&generation.facts),
                    domain,
                )
            });
        domain.sort_by_key(|(key, _)| *key);
        let (destination_v4, destination_v6, source_v4, source_v6, mac) = facts.map_or(
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()),
            |facts| {
                (
                    Self::fact_snapshot(&facts.destination_v4),
                    Self::fact_snapshot(&facts.destination_v6),
                    Self::fact_snapshot(&facts.source_v4),
                    Self::fact_snapshot(&facts.source_v6),
                    Self::fact_snapshot(&facts.mac),
                )
            },
        );
        MockRoutingSnapshot {
            active_slot: self.active_slot,
            descriptor: self.descriptor,
            plan_fingerprint: fingerprint,
            rule_count,
            destination_v4,
            destination_v6,
            source_v4,
            source_v6,
            mac,
            domain,
        }
    }

    fn take_routing_fault(&mut self, phase: RoutingPushPhase) -> anyhow::Result<()> {
        if let Some((configured, remaining)) = self.routing_fault
            && configured == phase
        {
            self.routing_fault = (remaining > 1).then_some((configured, remaining - 1));
            anyhow::bail!("injected routing push failure at {phase:?}");
        }
        Ok(())
    }

    #[cfg(test)]
    fn take_projection_fault(
        &mut self,
        operation: ProjectionMapOperation,
    ) -> Result<(), super::DomainRouteWriteError> {
        self.projection_writes.push(operation);
        if let Some((configured, remaining, map_full)) = self.projection_fault
            && configured == operation
        {
            self.projection_fault =
                (remaining > 1).then_some((configured, remaining - 1, map_full));
            if map_full {
                return Err(super::DomainRouteWriteError::MapFull);
            }
            return Err(super::DomainRouteWriteError::Other(anyhow::anyhow!(
                "injected projection {operation:?} failure"
            )));
        }
        Ok(())
    }

    // These convert repr(C) types to fixed-size byte arrays so they
    // can be used as HashMap keys (which require Hash + Eq).

    /// Convert a TuplesKey into a 40-byte array (includes repr(C) padding).
    fn tuples_key_bytes(key: &TuplesKey) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..16].copy_from_slice(unsafe { &key.src_ip.u6_addr8 });
        buf[16..32].copy_from_slice(unsafe { &key.dst_ip.u6_addr8 });
        buf[32..34].copy_from_slice(&key.src_port.to_ne_bytes());
        buf[34..36].copy_from_slice(&key.dst_port.to_ne_bytes());
        buf[36] = key.l4proto;
        // bytes 37..40 are padding (already zero)
        buf
    }

    /// Convert a RedirectTuple into its exact 40-byte `repr(C)` map key.
    fn redirect_tuple_bytes(key: &RedirectTuple) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..16].copy_from_slice(unsafe { &key.src_ip.u6_addr8 });
        buf[16..32].copy_from_slice(unsafe { &key.dst_ip.u6_addr8 });
        buf[32..34].copy_from_slice(&key.src_port.to_ne_bytes());
        buf[34..36].copy_from_slice(&key.dst_port.to_ne_bytes());
        buf[36] = key.l4proto;
        buf
    }

    /// Convert an LpmKey into a 20-byte array.
    fn lpm_key_bytes(key: &LpmKey) -> [u8; 20] {
        super::maps::lpm_key_bytes(key)
    }

    /// Reverse of tuples_key_bytes.
    fn bytes_to_tuples_key(buf: &[u8; 40]) -> TuplesKey {
        TuplesKey {
            src_ip: honk_ebpf_common::dae_ip::In6Addr {
                u6_addr8: buf[0..16].try_into().unwrap(),
            },
            dst_ip: honk_ebpf_common::dae_ip::In6Addr {
                u6_addr8: buf[16..32].try_into().unwrap(),
            },
            src_port: u16::from_ne_bytes([buf[32], buf[33]]),
            dst_port: u16::from_ne_bytes([buf[34], buf[35]]),
            l4proto: buf[36],
            padding: [0; 3],
        }
    }

    /// Reverse of redirect_tuple_bytes.
    fn bytes_to_redirect_tuple(buf: &[u8; 40]) -> RedirectTuple {
        RedirectTuple {
            src_ip: honk_ebpf_common::dae_ip::In6Addr {
                u6_addr8: buf[0..16].try_into().unwrap(),
            },
            dst_ip: honk_ebpf_common::dae_ip::In6Addr {
                u6_addr8: buf[16..32].try_into().unwrap(),
            },
            src_port: u16::from_ne_bytes([buf[32], buf[33]]),
            dst_port: u16::from_ne_bytes([buf[34], buf[35]]),
            l4proto: buf[36],
            padding: [0; 3],
        }
    }
}

#[async_trait]
impl EbpfBackend for MockEbpfBackend {
    fn observe_datapath(&self) -> super::DatapathObservation {
        #[cfg(test)]
        if let Some(observation) = &self.datapath_observation_fixture {
            return observation.clone();
        }
        super::DatapathObservation::unknown(super::DatapathKind::Mock)
    }

    #[cfg(test)]
    fn pname_support(&self) -> super::PnameSupport {
        self.pname_support
    }

    fn inject_routing_fault(
        &mut self,
        phase: RoutingPushPhase,
        times: usize,
    ) -> anyhow::Result<()> {
        self.routing_fault = (times != 0).then_some((phase, times));
        Ok(())
    }

    #[cfg(test)]
    fn inject_projection_fault(
        &mut self,
        operation: ProjectionMapOperation,
        times: usize,
        map_full: bool,
    ) -> anyhow::Result<()> {
        self.projection_fault = (times != 0).then_some((operation, times, map_full));
        Ok(())
    }

    #[cfg(test)]
    fn inject_domain_bitmap_add_fault(&mut self, times: usize) -> anyhow::Result<()> {
        self.domain_bitmap_add_faults = times;
        Ok(())
    }

    #[cfg(test)]
    fn projection_map_snapshot(&self) -> Vec<([u8; 20], DomainRouting)> {
        let mut snapshot = self
            .routing_generation
            .as_ref()
            .map(|generation| {
                generation
                    .domain
                    .iter()
                    .map(|(key, bitmap)| {
                        (
                            Self::lpm_key_bytes(&LpmKey {
                                prefix_len: 128,
                                data: *key,
                            }),
                            *bitmap,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        snapshot.sort_by_key(|(key, _)| *key);
        snapshot
    }

    #[cfg(test)]
    fn projection_write_log(&self) -> Vec<ProjectionMapOperation> {
        self.projection_writes.clone()
    }

    #[cfg(test)]
    fn clear_projection_write_log(&mut self) {
        self.projection_writes.clear();
    }
    fn publish_listener_sockets(
        &mut self,
        tcp4_fd: std::os::fd::RawFd,
        tcp6_fd: Option<std::os::fd::RawFd>,
        udp4_fds: &[std::os::fd::RawFd],
        udp6_fds: &[std::os::fd::RawFd],
    ) -> anyhow::Result<()> {
        self.listener_socket_slots.insert(0, tcp4_fd);
        if let Some(fd) = tcp6_fd {
            self.listener_socket_slots.insert(1, fd);
        }
        for (base, fds) in [(2, udp4_fds), (6, udp6_fds)] {
            for (offset, fd) in fds.iter().enumerate() {
                self.listener_socket_slots.insert(base + offset as u32, *fd);
            }
        }
        self.listener_sockets_published = true;
        Ok(())
    }

    fn clear_listener_sockets(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.datapath_ready,
            "datapath admission must be closed before clearing listeners"
        );
        self.listener_sockets_published = false;
        for key in 0..10 {
            #[cfg(test)]
            if self.listener_clear_fault_at == Some(key) {
                self.listener_clear_fault_at = None;
                anyhow::bail!("injected listener clear failure");
            }
            self.listener_socket_slots.remove(&key);
        }
        Ok(())
    }

    fn set_datapath_ready(&mut self, ready: bool) -> anyhow::Result<()> {
        if ready && !self.listener_sockets_published {
            anyhow::bail!("listener socket generation is not fully published");
        }
        self.datapath_ready = ready;
        Ok(())
    }

    fn set_datapath_flags(&mut self, flags: u32) -> anyhow::Result<()> {
        self.datapath_flags_writes.lock().push(flags);
        #[cfg(test)]
        {
            self.datapath_flags_writes_after_arm =
                self.datapath_flags_writes_after_arm.saturating_add(1);
            let ordinal = self.datapath_flags_writes_after_arm;
            let failed = self.datapath_flags_fault_nth == Some(ordinal);
            self.datapath_flags_write_trace
                .push(DatapathFlagsWriteTrace {
                    ordinal,
                    origin: std::mem::take(&mut self.datapath_flags_write_origin),
                    flags,
                    failed,
                });
            if failed {
                self.datapath_flags_fault_nth = None;
                anyhow::bail!("injected datapath flags write failure at ordinal {ordinal}");
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn arm_datapath_flags_write_fault(&mut self, nth: usize) -> anyhow::Result<()> {
        anyhow::ensure!(nth != 0, "datapath flags write ordinal must be non-zero");
        self.datapath_flags_fault_nth = Some(nth);
        self.datapath_flags_writes_after_arm = 0;
        Ok(())
    }

    #[cfg(test)]
    fn arm_quiesce_fault(&mut self) {
        self.fail_next_quiesce = true;
    }

    #[cfg(test)]
    fn mark_datapath_flags_write_origin(&mut self, origin: DatapathFlagsWriteOrigin) {
        self.datapath_flags_write_origin = origin;
    }

    #[cfg(test)]
    fn datapath_flags_write_log(&self) -> Vec<u32> {
        self.datapath_flags_writes.lock().clone()
    }

    #[cfg(test)]
    fn datapath_flags_write_trace(&self) -> Vec<DatapathFlagsWriteTrace> {
        self.datapath_flags_write_trace.clone()
    }

    #[cfg(test)]
    fn clear_datapath_flags_write_log(&mut self) {
        self.datapath_flags_writes.lock().clear();
        self.datapath_flags_write_trace.clear();
        self.datapath_flags_writes_after_arm = 0;
    }

    fn quiesce_udp_staging(&mut self) -> anyhow::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_quiesce) {
            anyhow::bail!("injected quiesce failure");
        }
        let staged = self
            .udp_conn_states
            .iter()
            .filter(|(_, state)| udp_state_is_staged(state.state))
            .map(|(key, state)| {
                (
                    Self::bytes_to_tuples_key(key),
                    state.decision_token,
                    state.incarnation,
                )
            })
            .collect::<Vec<_>>();
        retire_staged_udp(&staged, |requests, outcomes| {
            self.retire_batch(requests, outcomes)
        })?;
        if self.routing_generation.is_some() {
            let generation = self
                .next_generation
                .checked_add(1)
                .filter(|generation| *generation <= DNS_ROUTE_GENERATION_MAX)
                .ok_or_else(|| anyhow::anyhow!("routing generation counter exhausted"))?;
            self.next_generation = generation;
            self.descriptor.generation = generation;
        }
        Ok(())
    }

    fn publish_routing_plan(
        &mut self,
        plan: &crate::control::routing_matcher::RoutingPushPlan,
        learned_domains: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()> {
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("routing generation counter exhausted"))?;
        anyhow::ensure!(
            generation <= DNS_ROUTE_GENERATION_MAX,
            "routing generation counter exhausted at {DNS_ROUTE_GENERATION_MAX}"
        );
        anyhow::ensure!(
            self.active_slot < 2,
            "invalid active routing slot {}",
            self.active_slot
        );
        let slot = self.active_slot ^ 1;
        let trace_policy = if plan.trace_enabled() {
            self.next_trace_policy = self.next_trace_policy.saturating_add(1);
            self.next_trace_policy
        } else {
            0
        };
        self.take_routing_fault(RoutingPushPhase::DomainRouting)?;
        let domain: HashMap<_, _> = learned_domains
            .iter()
            .map(|(key, bitmap)| (key.data, *bitmap))
            .collect();
        self.take_routing_fault(RoutingPushPhase::DestinationLpm)?;
        self.take_routing_fault(RoutingPushPhase::SourceLpm)?;
        self.take_routing_fault(RoutingPushPhase::MacLpm)?;
        let domain_write_count = domain.len();
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::FactMaps(slot));
        self.take_routing_fault(RoutingPushPhase::Program)?;
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Program(slot));
        self.take_routing_fault(RoutingPushPhase::Attach)?;
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Attach(slot));

        let domain_map_id = self
            .next_domain_map_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("domain map id counter exhausted"))?;
        let candidate = MockRoutingGeneration {
            fingerprint: plan.fingerprint,
            rule_count: plan.rules.len(),
            facts: plan.facts.clone(),
            domain,
        };
        self.take_routing_fault(RoutingPushPhase::Root)?;
        self.routing_generation = Some(candidate);
        self.active_slot = slot;
        self.descriptor = RoutingPolicyDescriptor {
            slot,
            features: plan.features,
            generation,
            domain_map_id,
            trace_policy,
        };
        self.next_generation = generation;
        self.next_domain_map_id = domain_map_id;
        self.routing_publication_order
            .push(MockRoutingPublicationWrite::Root(slot));
        self.count_routing_writes(
            (plan.facts.destination_v4.len()
                + plan.facts.destination_v6.len()
                + plan.facts.source_v4.len()
                + plan.facts.source_v6.len()
                + plan.facts.mac.len()
                + plan.rules.len()
                + domain_write_count
                + 1) as u64,
        );
        Ok(())
    }

    fn routing_policy_generation(&self) -> u64 {
        self.next_generation
    }

    fn active_routing_slot(&self) -> anyhow::Result<u32> {
        Ok(self.active_slot)
    }

    fn add_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.domain_bitmap_add_faults > 0 {
            self.domain_bitmap_add_faults -= 1;
            anyhow::bail!("injected domain bitmap write failure");
        }
        let generation = self
            .routing_generation
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no active routing generation"))?;
        let current = generation.domain.entry(ip_key.data).or_default();
        for (current, update) in current.bitmap.iter_mut().zip(bitmap.bitmap) {
            *current |= update;
        }
        self.count_routing_writes(1);
        Ok(())
    }

    fn set_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> Result<(), super::DomainRouteWriteError> {
        #[cfg(test)]
        self.take_projection_fault(ProjectionMapOperation::Set)?;
        let generation = self.routing_generation.as_mut().ok_or_else(|| {
            super::DomainRouteWriteError::Other(anyhow::anyhow!("no active routing generation"))
        })?;
        generation.domain.insert(ip_key.data, *bitmap);
        self.count_routing_writes(1);
        Ok(())
    }

    fn remove_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
    ) -> Result<(), super::DomainRouteWriteError> {
        #[cfg(test)]
        self.take_projection_fault(ProjectionMapOperation::Remove)?;
        let generation = self.routing_generation.as_mut().ok_or_else(|| {
            super::DomainRouteWriteError::Other(anyhow::anyhow!("no active routing generation"))
        })?;
        generation.domain.remove(&ip_key.data);
        self.count_routing_writes(1);
        Ok(())
    }

    fn conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        Ok(self
            .conn_states(key.l4proto)
            .get(&Self::tuples_key_bytes(key))
            .copied())
    }

    #[cfg(test)]
    fn tcp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()> {
        self.tcp_conn_states
            .insert(Self::tuples_key_bytes(key), *state);
        Ok(())
    }

    fn udp_flow_owner(
        &self,
        token: u32,
        state: Option<ConnState>,
    ) -> anyhow::Result<super::UdpFlowOwner> {
        let Some(state) = state else {
            anyhow::ensure!(token == 0, "model staged UDP admission has no conn-state");
            return super::UdpFlowOwner::new(token, None);
        };
        anyhow::ensure!(
            state.decision_token == token,
            "model UDP decision token mismatch"
        );
        super::UdpFlowOwner::new(token, (state.incarnation != 0).then_some(state.incarnation))
    }

    #[cfg(test)]
    fn udp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()> {
        self.udp_conn_states
            .insert(Self::tuples_key_bytes(key), *state);
        Ok(())
    }

    fn commit_udp_decision(
        &mut self,
        key: &TuplesKey,
        token: u32,
        transition: UdpDecisionTransition,
    ) -> anyhow::Result<UdpDecisionCommitResult> {
        validate_udp_decision_transition(transition)?;
        if token == 0 {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let key_bytes = Self::tuples_key_bytes(key);
        let Some(state) = self.udp_conn_states.get(&key_bytes).copied() else {
            return Ok(UdpDecisionCommitResult::Missing);
        };
        if state.decision_token != token {
            return Ok(UdpDecisionCommitResult::TokenMismatch);
        }
        let handoff = self.routing_handoffs.lock().get(&key_bytes).copied();
        // Explicit model fixtures may commit a zero-identity staged flow.
        let track_key = Self::redirect_tuple_bytes(&RedirectTuple::from_tuples(key));
        let track = self.redirect_tracks.get(&track_key).copied();
        let plan = match plan_udp_commit(state, token, transition, handoff.as_ref(), track.as_ref())
        {
            Ok(plan) => plan,
            Err(result) => return Ok(result),
        };
        if plan.remove_handoff {
            self.routing_handoffs.lock().remove(&key_bytes);
        }
        match plan.redirect {
            Some(RedirectEffect::Rewrite(track)) => {
                self.redirect_tracks.insert(track_key, track);
            }
            Some(RedirectEffect::Remove) => {
                self.redirect_tracks.remove(&track_key);
            }
            None => {}
        }
        self.udp_conn_states.insert(key_bytes, plan.state);
        Ok(UdpDecisionCommitResult::Applied)
    }
    fn adopt_tcp(
        &self,
        _fd: std::os::fd::BorrowedFd<'_>,
        tuples: &TuplesKey,
        _errors: super::TcpPinErrorSink,
    ) -> anyhow::Result<super::TcpAdoption> {
        let current = self
            .conn_state_lookup(tuples)?
            .ok_or_else(|| anyhow::anyhow!("accepted TCP flow has no conn-state: {tuples:?}"))?;
        Ok(super::TcpAdoption {
            incarnation: current.incarnation,
            handoff: self.routing_handoff_lookup(tuples)?,
            pin: super::TcpPin::Model,
        })
    }

    #[cfg(test)]
    fn tcp_socket_ownership(
        &self,
        _fd: std::os::fd::BorrowedFd<'_>,
    ) -> anyhow::Result<TcpSocketOwnership> {
        Ok(TcpSocketOwnership::Model)
    }

    fn take_expiry_hints(&mut self) -> Option<tokio::sync::mpsc::Receiver<FlowExpiryHint>> {
        None
    }

    fn tcp_request_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut super::TcpRequestChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut chunk = Vec::with_capacity(chunk_size.max(1));
        for (&(address, cookie), binding) in &self.tcp_request_bindings {
            chunk.push((TcpRequestKey { address, cookie }, *binding));
            if chunk.len() == chunk_size.max(1) {
                if !visit(&chunk) {
                    return Ok(());
                }
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            visit(&chunk);
        }
        Ok(())
    }

    fn retire_batch(
        &mut self,
        requests: &[RetireRequest<'_>],
        outcomes: &mut [RetireOutcome],
    ) -> Result<RetireCounts, RetireError> {
        outcomes.fill(RetireOutcome::NotRun);
        let mut counts = RetireCounts::default();
        let result = self
            .retire_model_batch(requests, outcomes, &mut counts)
            .map(|()| counts)
            .map_err(|source| RetireError { counts, source });
        account_retirement(&result);
        result
    }

    fn verify_udp_decision_sequence(&self) -> anyhow::Result<()> {
        self.udp_decision_sequence_status().map(|_| ())
    }
    fn udp_decision_sequence_status(&self) -> anyhow::Result<UdpDecisionSequenceStatus> {
        anyhow::ensure!(
            self.udp_decision_sequence_next <= honk_ebpf_common::UDP_DECISION_SEQUENCE_MASK,
            "invalid mock UDP decision sequence"
        );
        anyhow::ensure!(
            self.udp_decision_sequence_generation <= honk_ebpf_common::UDP_DECISION_GENERATION_MASK,
            "invalid mock UDP decision generation"
        );
        Ok(UdpDecisionSequenceStatus {
            next: self.udp_decision_sequence_next,
            generation: self.udp_decision_sequence_generation,
        })
    }

    fn reset_udp_decision_sequence(&mut self, generation: u32) -> anyhow::Result<bool> {
        anyhow::ensure!(
            generation <= honk_ebpf_common::UDP_DECISION_GENERATION_MASK,
            "invalid UDP decision generation {generation}"
        );
        anyhow::ensure!(
            self.udp_decision_sequence_status()?.exhausted(),
            "UDP decision sequence is not exhausted"
        );
        let conflicts_with_rollback = |token| {
            token != 0 && honk_ebpf_common::udp_decision_token_generation(token) >= generation
        };
        let generation_is_live = self
            .udp_conn_states
            .values()
            .any(|state| conflicts_with_rollback(state.decision_token))
            || self
                .retire_fences
                .values()
                .any(|fence| conflicts_with_rollback(fence.decision_token))
            || self
                .routing_handoffs
                .lock()
                .values()
                .any(|entry| conflicts_with_rollback(entry.result.decision_token))
            || self
                .redirect_tracks
                .values()
                .any(|entry| conflicts_with_rollback(entry.decision_token));
        if generation_is_live {
            return Ok(false);
        }
        self.udp_decision_sequence_next = 0;
        self.udp_decision_sequence_generation = generation;
        Ok(true)
    }

    fn routing_handoff_lookup(
        &self,
        key: &TuplesKey,
    ) -> anyhow::Result<Option<RoutingHandoffEntry>> {
        Ok(self
            .routing_handoffs
            .lock()
            .get(&Self::tuples_key_bytes(key))
            .copied())
    }

    fn redirect_track_lookup(&self, key: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>> {
        Ok(self
            .redirect_tracks
            .get(&Self::redirect_tuple_bytes(key))
            .copied())
    }

    #[cfg(test)]
    fn redirect_track_store(
        &mut self,
        key: &RedirectTuple,
        entry: &RedirectEntry,
    ) -> anyhow::Result<()> {
        self.redirect_tracks
            .insert(Self::redirect_tuple_bytes(key), *entry);
        Ok(())
    }

    #[cfg(feature = "native-api")]
    fn bind_kernel_trace_dictionary(
        &mut self,
        dictionary: crate::observe::flows::kernel::KernelTraceDictionary,
    ) {
        if let Some(owner) = &self.routing_generation {
            self.trace_dictionaries.bind(
                self.descriptor.trace_policy,
                owner.fingerprint,
                dictionary,
            );
        }
    }

    #[cfg(feature = "native-api")]
    fn capture_kernel_route(
        &self,
        key: &TuplesKey,
        reference: crate::observe::flows::kernel::KernelRouteReference,
    ) -> Result<crate::observe::flows::kernel::CapturedKernelRoute, &'static str> {
        if reference.trace_id == 0 {
            return Err("kernel_trace_not_captured");
        }
        if reference.trace_id == ROUTE_TRACE_LOST {
            return Err("kernel_trace_lost");
        }
        let witness = self
            .route_witnesses
            .get(&reference.trace_id)
            .ok_or("kernel_trace_sidecar_missing")?;
        self.trace_dictionaries.capture(witness, key, reference)
    }

    fn set_outbound_alive(
        &mut self,
        outbound: u8,
        domain: u32,
        ipver: u32,
        alive: bool,
    ) -> anyhow::Result<()> {
        let key = (outbound as u32)
            .wrapping_mul(6)
            .wrapping_add(domain.wrapping_mul(2))
            .wrapping_add(ipver);
        self.count_outbound_alive_write();
        self.outbound_alive.insert(key, if alive { 1 } else { 0 });
        Ok(())
    }

    fn get_outbound_alive(&self, outbound: u8, domain: u32, ipver: u32) -> anyhow::Result<bool> {
        let key = (outbound as u32)
            .wrapping_mul(6)
            .wrapping_add(domain.wrapping_mul(2))
            .wrapping_add(ipver);
        Ok(self.outbound_alive.get(&key).copied().unwrap_or(0) != 0)
    }

    fn get_bpf_stats(&self, key: u32) -> anyhow::Result<Option<u64>> {
        Ok(self.bpf_stats.get(&key).copied())
    }

    fn redirect_track_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut super::RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut chunk = Vec::with_capacity(chunk_size.max(1));
        for (key, entry) in &self.redirect_tracks {
            chunk.push((Self::bytes_to_redirect_tuple(key), *entry));
            if chunk.len() == chunk_size.max(1) {
                if !visit(&chunk) {
                    return Ok(());
                }
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            visit(&chunk);
        }
        Ok(())
    }

    fn routing_handoff_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut super::RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut chunk = Vec::with_capacity(chunk_size.max(1));
        for (key, entry) in self.routing_handoffs.lock().iter() {
            chunk.push((Self::bytes_to_tuples_key(key), *entry));
            if chunk.len() == chunk_size.max(1) {
                if !visit(&chunk) {
                    return Ok(());
                }
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            visit(&chunk);
        }
        Ok(())
    }

    fn conn_state_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut super::ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut chunk = Vec::with_capacity(chunk_size.max(1));
        for (key, entry) in self
            .tcp_conn_states
            .iter()
            .chain(self.udp_conn_states.iter())
        {
            chunk.push((Self::bytes_to_tuples_key(key), *entry));
            if chunk.len() == chunk_size.max(1) {
                if !visit(&chunk) {
                    return Ok(());
                }
                chunk.clear();
            }
        }
        if !chunk.is_empty() {
            visit(&chunk);
        }
        Ok(())
    }

    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        self.detach_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn attach_dynamic_interface(
        &mut self,
        _ifname: &str,
        _role: super::IfaceRole,
        _single_homed: bool,
    ) -> anyhow::Result<super::DynamicHooks> {
        #[cfg(test)]
        anyhow::ensure!(
            !self.dynamic_attach_fault,
            "injected dynamic attach failure"
        );
        self.dynamic_attach_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(super::DynamicHooks {
            ingress: true,
            egress: true,
        })
    }

    fn forget_dynamic_interface(&mut self, _ifindex: u32) {
        self.dynamic_forget_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        self.datapath_ready = false;
        self.listener_sockets_published = false;
        self.listener_socket_slots.clear();
        self.routing_generation = None;
        self.descriptor = RoutingPolicyDescriptor::default();
        self.tcp_conn_states.clear();
        self.udp_conn_states.clear();
        self.redirect_tracks.clear();
        self.routing_handoffs.get_mut().clear();
        self.tcp_request_bindings.clear();
        self.retire_fences.clear();
        self.route_witnesses.clear();
        self.outbound_alive.clear();
        self.bpf_stats.clear();
        Ok(())
    }
}

#[cfg(test)]
mod batch_retirement_tests {
    use super::*;

    #[test]
    fn auxiliary_owner_mismatch_refuses_retirement_and_commit_without_mutation() {
        for operation in 0..7 {
            let mut backend = MockEbpfBackend::new();
            let key = TuplesKey {
                l4proto: if operation == 0 { 6 } else { 17 },
                ..Default::default()
            };
            let state = ConnState {
                incarnation: 1,
                decision_token: 7,
                state: UdpDecisionState::Pending as u8,
                ..Default::default()
            };
            backend.seed_staged_udp_flow(&key, state);
            if operation == 0 {
                backend.udp_conn_states.clear();
                backend.tcp_conn_state_store(&key, &state).unwrap();
            }
            let raw = MockEbpfBackend::tuples_key_bytes(&key);
            if matches!(operation, 5 | 6) {
                let track_raw =
                    MockEbpfBackend::redirect_tuple_bytes(&RedirectTuple::from_tuples(&key));
                backend
                    .redirect_tracks
                    .get_mut(&track_raw)
                    .unwrap()
                    .decision_token = 8;
            } else {
                backend
                    .routing_handoffs
                    .get_mut()
                    .get_mut(&raw)
                    .unwrap()
                    .result
                    .decision_token = 8;
            }
            let outcome = if matches!(operation, 4 | 5) {
                backend
                    .commit_udp_decision(&key, 7, UdpDecisionTransition::Block)
                    .unwrap()
            } else {
                let kind = match operation {
                    0 => RetireKind::Tcp { incarnation: 1 },
                    1 | 6 => RetireKind::Udp {
                        token: 7,
                        incarnation: Some(1),
                        pending_only: true,
                    },
                    2 => RetireKind::ExpiredConn {
                        expected: &state,
                        expired_before_ns: 0,
                    },
                    _ => RetireKind::ExpiryHint {
                        incarnation: 1,
                        now_ns: u64::MAX,
                    },
                };
                let (counts, outcome) = retire_fixture(&mut backend, key, kind);
                assert_eq!(counts, RetireCounts::default());
                outcome
            };
            assert_eq!(outcome, UdpDecisionCommitResult::TokenMismatch);
            let retained = backend.conn_state_lookup(&key).unwrap().unwrap();
            assert_eq!(
                (
                    retained.incarnation,
                    retained.decision_token,
                    retained.state
                ),
                (1, 7, state.state)
            );
            assert_eq!(
                backend
                    .routing_handoff_lookup(&key)
                    .unwrap()
                    .unwrap()
                    .result
                    .decision_token,
                if matches!(operation, 5 | 6) { 7 } else { 8 }
            );
            assert_eq!(
                backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                    .unwrap()
                    .unwrap()
                    .decision_token,
                if matches!(operation, 5 | 6) { 8 } else { 7 }
            );
        }
    }

    #[test]
    fn hint_auxiliary_expiry_refuses_mismatched_tokens_without_conn() {
        let mut backend = MockEbpfBackend::new();
        let key = TuplesKey {
            l4proto: 17,
            ..Default::default()
        };
        backend.seed_staged_udp_flow(
            &key,
            ConnState {
                incarnation: 1,
                decision_token: 7,
                state: UdpDecisionState::Pending as u8,
                ..Default::default()
            },
        );
        backend.udp_conn_states.clear();
        let track_raw = MockEbpfBackend::redirect_tuple_bytes(&RedirectTuple::from_tuples(&key));
        backend
            .redirect_tracks
            .get_mut(&track_raw)
            .unwrap()
            .decision_token = 8;
        let kind = RetireKind::ExpiryHint {
            incarnation: 1,
            now_ns: 121_000_000_000,
        };
        let (counts, outcome) = retire_fixture(&mut backend, key, kind);
        assert_eq!(outcome, UdpDecisionCommitResult::TokenMismatch);
        assert_eq!(counts, RetireCounts::default());
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
        assert_eq!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .unwrap()
                .decision_token,
            8
        );
        backend
            .redirect_tracks
            .get_mut(&track_raw)
            .unwrap()
            .decision_token = 7;
        let (counts, outcome) = retire_fixture(&mut backend, key, kind);
        assert_eq!(outcome, UdpDecisionCommitResult::Applied);
        assert_eq!(
            counts,
            RetireCounts {
                handoff: 1,
                redirect: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn expired_conn_retirement_reclaims_matching_auxiliaries() {
        for proto in [6, 17] {
            let mut backend = MockEbpfBackend::new();
            let key = TuplesKey {
                l4proto: proto,
                ..Default::default()
            };
            let state = ConnState {
                incarnation: 1,
                decision_token: 7,
                state: UdpDecisionState::Pending as u8,
                ..Default::default()
            };
            backend.seed_staged_udp_flow(&key, state);
            if proto == 6 {
                backend.udp_conn_states.clear();
                backend.tcp_conn_state_store(&key, &state).unwrap();
            }
            let (counts, outcome) = retire_fixture(
                &mut backend,
                key,
                RetireKind::ExpiredConn {
                    expected: &state,
                    expired_before_ns: 0,
                },
            );
            assert_eq!(outcome, UdpDecisionCommitResult::Applied);
            assert_eq!(
                counts,
                RetireCounts {
                    conn: 1,
                    handoff: 1,
                    redirect: 1,
                    request: 0
                }
            );
            assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
            assert!(
                backend
                    .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn udp_flow_owner_validates_incarnations_and_preserves_model_identity() {
        use super::super::UdpFlowOwner;
        use honk_ebpf_common::conn::FLOW_INCARNATION_MAX;

        assert_eq!(UdpFlowOwner::new(0, None).unwrap().incarnation(), None);
        for incarnation in [0, FLOW_INCARNATION_MAX + 1, u64::MAX] {
            assert!(UdpFlowOwner::new(7, Some(incarnation)).is_err());
        }
        let backend = MockEbpfBackend::new();
        assert_eq!(backend.udp_flow_owner(0, None).unwrap().incarnation(), None);
        assert!(backend.udp_flow_owner(7, None).is_err());
        for incarnation in [0, 1, FLOW_INCARNATION_MAX] {
            let state = Some(ConnState {
                decision_token: 7,
                incarnation,
                ..Default::default()
            });
            let owner = backend.udp_flow_owner(7, state).unwrap();
            assert_eq!(owner.token, 7);
            assert_eq!(
                owner.incarnation(),
                (incarnation != 0).then_some(incarnation)
            );
            assert!(backend.udp_flow_owner(8, state).is_err());
        }
        assert!(
            backend
                .udp_flow_owner(
                    0,
                    Some(ConnState {
                        incarnation: FLOW_INCARNATION_MAX + 1,
                        ..Default::default()
                    }),
                )
                .is_err()
        );
    }

    #[test]
    fn udp_admission_checks_captured_owner_with_model_and_stateless_exemptions() {
        use super::super::UdpFlowOwner;

        let mut backend = MockEbpfBackend::new();
        let key = TuplesKey {
            src_port: 41000,
            dst_port: 443,
            l4proto: 17,
            ..Default::default()
        };
        let model = UdpFlowOwner::new(0, None).unwrap();
        assert!(backend.verify_udp_admission(&key, model).unwrap().is_none());
        assert!(
            backend
                .verify_udp_admission(&key, UdpFlowOwner::new(7, None).unwrap())
                .is_err()
        );
        for incarnation in [0, 41] {
            backend.seed_staged_udp_flow(
                &key,
                ConnState {
                    decision_token: 7,
                    incarnation,
                    state: UdpDecisionState::Pending as u8,
                    ..Default::default()
                },
            );
            let owner = backend
                .udp_flow_owner(7, backend.conn_state_lookup(&key).unwrap())
                .unwrap();
            assert!(backend.verify_udp_admission(&key, owner).unwrap().is_some());
            assert!(
                backend
                    .verify_udp_admission(&key, UdpFlowOwner::new(7, Some(42)).unwrap())
                    .is_err()
            );
            let handoff = backend
                .routing_handoffs
                .get_mut()
                .get_mut(&MockEbpfBackend::tuples_key_bytes(&key))
                .unwrap();
            handoff.result.decision_token = 8;
            assert!(backend.verify_udp_admission(&key, owner).is_err());
        }
        backend
            .udp_conn_state_store(
                &key,
                &ConnState {
                    incarnation: 41,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(backend.verify_udp_admission(&key, model).is_err());
        let stateless = TuplesKey {
            dst_port: 53,
            ..key
        };
        assert!(
            backend
                .verify_udp_admission(&stateless, model)
                .unwrap()
                .is_none()
        );
        backend.routing_handoffs.get_mut().insert(
            MockEbpfBackend::tuples_key_bytes(&stateless),
            RoutingHandoffEntry {
                result: RoutingResult {
                    decision_token: 7,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert!(backend.verify_udp_admission(&stateless, model).is_err());
        backend
            .routing_handoffs
            .get_mut()
            .get_mut(&MockEbpfBackend::tuples_key_bytes(&stateless))
            .unwrap()
            .result
            .decision_token = 0;
        assert!(
            backend
                .verify_udp_admission(&stateless, model)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn expiry_hint_ages_auxiliaries_without_requiring_expired_conn_state() {
        let mut backend = MockEbpfBackend::new();
        let key = TuplesKey {
            l4proto: 17,
            ..Default::default()
        };
        backend.seed_staged_udp_flow(
            &key,
            ConnState {
                incarnation: 1,
                last_seen_ns: 31_000_000_000,
                decision_token: 7,
                state: UdpDecisionState::Pending as u8,
                ..Default::default()
            },
        );
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiryHint {
                incarnation: 2,
                now_ns: 31_000_000_000,
            },
        );
        assert_eq!(counts, RetireCounts::default());
        assert_eq!(outcome, UdpDecisionCommitResult::Superseded);
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiryHint {
                incarnation: 1,
                now_ns: 31_000_000_000,
            },
        );
        assert_eq!(
            counts,
            RetireCounts {
                handoff: 1,
                ..Default::default()
            }
        );
        assert_eq!(outcome, UdpDecisionCommitResult::Applied);
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_some()
        );
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiryHint {
                incarnation: 1,
                now_ns: 121_000_000_000,
            },
        );
        assert_eq!(
            counts,
            RetireCounts {
                redirect: 1,
                ..Default::default()
            }
        );
        assert_eq!(outcome, UdpDecisionCommitResult::Applied);
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            backend
                .conn_state_lookup(&key)
                .unwrap()
                .unwrap()
                .incarnation,
            1
        );
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiryHint {
                incarnation: 1,
                now_ns: 31_000_000_001 + honk_ebpf_common::conn::UDP_CONN_STATE_TIMEOUT_NS,
            },
        );
        assert_eq!(counts.conn, 1);
        assert_eq!(outcome, UdpDecisionCommitResult::Applied);
        assert!(backend.conn_state_lookup(&key).unwrap().is_none());
    }

    #[test]
    fn unchanged_timestamp_does_not_authorize_stale_snapshot_cleanup() {
        let mut backend = MockEbpfBackend::new();
        let key = TuplesKey {
            l4proto: 6,
            ..Default::default()
        };
        let old = ConnState {
            incarnation: 1,
            last_seen_ns: 1,
            ..Default::default()
        };
        let current = ConnState {
            incarnation: 2,
            ..old
        };
        backend.tcp_conn_state_store(&key, &current).unwrap();
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiredConn {
                expected: &old,
                expired_before_ns: 10,
            },
        );
        assert_eq!(counts.conn, 0);
        assert_eq!(outcome, UdpDecisionCommitResult::Superseded);
        assert_eq!(
            backend
                .conn_state_lookup(&key)
                .unwrap()
                .unwrap()
                .incarnation,
            2
        );
    }

    #[test]
    fn old_tcp_owner_cannot_retire_new_syn_with_same_timestamp() {
        let mut backend = MockEbpfBackend::new();
        let key = TuplesKey {
            l4proto: 6,
            ..Default::default()
        };
        let state = ConnState {
            incarnation: 2,
            last_seen_ns: 1,
            ..Default::default()
        };
        backend.tcp_conn_state_store(&key, &state).unwrap();
        backend.routing_handoffs.get_mut().insert(
            MockEbpfBackend::tuples_key_bytes(&key),
            RoutingHandoffEntry {
                incarnation: 2,
                ..Default::default()
            },
        );
        backend
            .redirect_track_store(
                &RedirectTuple::from_tuples(&key),
                &RedirectEntry {
                    incarnation: 2,
                    ..Default::default()
                },
            )
            .unwrap();
        let (counts, outcome) =
            retire_fixture(&mut backend, key, RetireKind::Tcp { incarnation: 1 });
        assert_eq!(outcome, UdpDecisionCommitResult::Superseded);
        assert_eq!(counts, RetireCounts::default());
        assert_eq!(
            backend
                .conn_state_lookup(&key)
                .unwrap()
                .unwrap()
                .incarnation,
            2
        );
        assert_eq!(
            backend
                .routing_handoff_lookup(&key)
                .unwrap()
                .unwrap()
                .incarnation,
            2
        );
        assert_eq!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .unwrap()
                .incarnation,
            2
        );
        let (counts, outcome) =
            retire_fixture(&mut backend, key, RetireKind::Tcp { incarnation: 2 });
        assert_eq!(outcome, UdpDecisionCommitResult::Applied);
        assert_eq!(
            counts,
            RetireCounts {
                conn: 1,
                redirect: 1,
                handoff: 1,
                request: 0
            }
        );
    }

    #[test]
    fn partial_failure_reports_only_completed_requests_and_real_deletions() {
        let mut backend = MockEbpfBackend::new();
        let key = TuplesKey {
            l4proto: 6,
            ..Default::default()
        };
        let state = ConnState::default();
        backend.tcp_conn_state_store(&key, &state).unwrap();
        let request = RetireRequest {
            key,
            kind: RetireKind::ExpiredConn {
                expected: &state,
                expired_before_ns: 0,
            },
        };
        let mut outcomes = [RetireOutcome::NotRun; 3];
        backend.retire_fault_after = Some(2);
        let error = backend
            .retire_batch(&[request; 3], &mut outcomes)
            .unwrap_err();
        assert_eq!(
            error.counts,
            RetireCounts {
                conn: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            outcomes,
            [
                RetireOutcome::Done(UdpDecisionCommitResult::Applied),
                RetireOutcome::Done(UdpDecisionCommitResult::Missing),
                RetireOutcome::NotRun
            ]
        );
        assert!(backend.conn_state_lookup(&key).unwrap().is_none());
        let mut outcomes = [RetireOutcome::Done(UdpDecisionCommitResult::Applied)];
        let error = backend.retire_batch(&[], &mut outcomes).unwrap_err();
        assert_eq!(error.counts, RetireCounts::default());
        assert_eq!(outcomes, [RetireOutcome::NotRun]);
    }

    #[test]
    fn request_expiry_uses_immutable_owner_and_scan_chunks() {
        let mut backend = MockEbpfBackend::new();
        let key = TuplesKey {
            l4proto: 6,
            ..Default::default()
        };
        let proof = TcpRequestKey {
            address: 10,
            cookie: 11,
        };
        let old = TcpSocketBinding {
            tuples: key,
            kind: TCP_BINDING_CHILD,
            handoff: RoutingHandoffEntry {
                incarnation: 1,
                last_seen_ns: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let fresh = TcpSocketBinding {
            handoff: RoutingHandoffEntry {
                incarnation: 2,
                ..old.handoff
            },
            ..old
        };
        backend
            .tcp_request_bindings
            .insert((proof.address, proof.cookie), fresh);
        backend
            .tcp_conn_state_store(
                &key,
                &ConnState {
                    incarnation: 2,
                    tcp_request_count: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        let mut scanned = 0;
        backend
            .tcp_request_for_each_chunk(1, &mut |chunk| {
                assert_eq!(chunk.len(), 1);
                assert_eq!(chunk[0].0.cookie, proof.cookie);
                scanned += chunk.len();
                false
            })
            .unwrap();
        assert_eq!(scanned, 1);
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiredRequest {
                request: &proof,
                expected: &old,
                expired_before_ns: 1,
            },
        );
        assert_eq!(counts.request, 0);
        assert_eq!(outcome, UdpDecisionCommitResult::Superseded);
        assert_eq!(
            backend
                .conn_state_lookup(&key)
                .unwrap()
                .unwrap()
                .tcp_request_count,
            1
        );
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::ExpiredRequest {
                request: &proof,
                expected: &fresh,
                expired_before_ns: 1,
            },
        );
        assert_eq!(counts.request, 1);
        assert_eq!(outcome, UdpDecisionCommitResult::Applied);
        assert_eq!(
            backend
                .conn_state_lookup(&key)
                .unwrap()
                .unwrap()
                .tcp_request_count,
            0
        );
        assert!(backend.tcp_request_bindings.is_empty());
        assert!(backend.take_expiry_hints().is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_ebpf_common::dae_ip::In6Addr;

    #[test]
    fn listener_clear_rejects_live_admission_and_fences_partial_failure() {
        let mut backend = MockEbpfBackend::new();
        backend
            .publish_listener_sockets(10, Some(11), &[12, 13, 14, 15], &[16, 17, 18, 19])
            .unwrap();
        backend.set_datapath_ready(true).unwrap();
        assert!(backend.clear_listener_sockets().is_err());
        assert!(backend.listener_sockets_published);
        assert_eq!(backend.listener_socket_slots.len(), 10);
        backend.set_datapath_ready(false).unwrap();
        backend.listener_clear_fault_at = Some(4);
        assert!(backend.clear_listener_sockets().is_err());
        assert!(!backend.listener_sockets_published);
        assert!(!backend.datapath_ready);
        assert!(!backend.listener_socket_slots.contains_key(&3));
        assert_eq!(backend.listener_socket_slots.get(&4), Some(&14));
        assert!(backend.set_datapath_ready(true).is_err());
        backend.clear_listener_sockets().unwrap();
        assert!(backend.listener_socket_slots.is_empty());
        assert!(backend.set_datapath_ready(true).is_err());
        backend
            .publish_listener_sockets(20, None, &[22, 23, 24, 25], &[])
            .unwrap();
        assert_eq!(backend.listener_socket_slots.len(), 5);
        assert!(!backend.listener_socket_slots.contains_key(&1));
        assert!(!backend.listener_socket_slots.contains_key(&6));
        backend.set_datapath_ready(true).unwrap();
    }

    fn decision_test_key() -> TuplesKey {
        let mut key: TuplesKey = unsafe { std::mem::zeroed() };
        key.dst_ip[15] = 1;
        key.src_ip[15] = 2;
        key.dst_port = 443;
        key.src_port = 53000;
        key.l4proto = 17;
        key
    }

    fn decision_test_meta(outbound: u8, mark: u32, dscp: u8) -> RoutingMeta {
        RoutingMeta {
            raw: outbound as u64
                | ((mark as u64) << 8)
                | (1 << 40)
                | ((dscp as u64) << 48)
                | ROUTING_META_FLAG_PUBLISHED,
        }
    }

    fn seed_staged_flow(backend: &mut MockEbpfBackend, key: &TuplesKey, token: u32) {
        backend.seed_staged_udp_flow(
            key,
            ConnState {
                state: UdpDecisionState::Pending as u8,
                decision_token: token,
                last_seen_ns: 1,
                meta: decision_test_meta(OutboundIndex::UserBase as u8, TPROXY_MARK, 5),
                pid: 99,
                ..Default::default()
            },
        );
    }

    #[test]
    fn udp_direct_transition_is_two_phase_and_preserves_metadata() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        seed_staged_flow(&mut backend, &key, 7);

        assert_eq!(
            backend
                .commit_udp_decision(&key, 7, UdpDecisionTransition::ArmDirect(0x1234))
                .unwrap(),
            UdpDecisionCommitResult::Applied
        );
        let armed = backend.conn_state_lookup(&key).unwrap().unwrap();
        let armed_raw = unsafe { armed.meta.raw };
        assert_eq!(armed.state, UdpDecisionState::DirectArmed as u8);
        assert_eq!(armed.decision_token, 7);
        assert_eq!(armed.pid, 99);
        assert_eq!(armed_raw & 0xff, OutboundIndex::Direct as u64);
        assert_eq!((armed_raw >> 8) & 0xffff_ffff, 0x1234);
        assert_eq!((armed_raw >> 48) & 0xff, 5);
        assert_eq!(armed_raw & ROUTING_META_FLAG_OFFLOAD, 0);
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_none()
        );

        assert_eq!(
            backend
                .commit_udp_decision(&key, 7, UdpDecisionTransition::ActivateDirect(0x5678))
                .unwrap(),
            UdpDecisionCommitResult::StateMismatch
        );
        assert_eq!(
            backend
                .commit_udp_decision(&key, 7, UdpDecisionTransition::ActivateDirect(0x1234))
                .unwrap(),
            UdpDecisionCommitResult::Applied
        );
        let active = backend.conn_state_lookup(&key).unwrap().unwrap();
        let active_raw = unsafe { active.meta.raw };
        assert_eq!(active.state, UdpDecisionState::None as u8);
        assert_eq!((active_raw >> 8) & 0xffff_ffff, 0x1234);
        assert_ne!(active_raw & ROUTING_META_FLAG_OFFLOAD, 0);
        assert_eq!(
            backend
                .commit_udp_decision(&key, 7, UdpDecisionTransition::ActivateDirect(0x1234))
                .unwrap(),
            UdpDecisionCommitResult::StateMismatch
        );
    }

    #[test]
    fn udp_proxy_transition_rewrites_exact_track() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        seed_staged_flow(&mut backend, &key, 11);
        assert_eq!(
            backend
                .commit_udp_decision(
                    &key,
                    11,
                    UdpDecisionTransition::ActivateProxy(OutboundIndex::UserBase as u8 + 2, 42),
                )
                .unwrap(),
            UdpDecisionCommitResult::Applied
        );
        let state = backend.conn_state_lookup(&key).unwrap().unwrap();
        let raw = unsafe { state.meta.raw };
        assert_eq!(state.state, UdpDecisionState::Proxy as u8);
        assert_eq!(raw & 0xff, (OutboundIndex::UserBase as u8 + 2) as u64);
        assert_eq!((raw >> 8) & 0xffff_ffff, 42);
        assert_eq!((raw >> 48) & 0xff, 5);
        let track = backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
            .unwrap()
            .unwrap();
        assert_eq!(track.decision_token, 11);
        assert_eq!(track.outbound, OutboundIndex::UserBase as u8 + 2);
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
        assert_eq!(
            retire_fixture(
                &mut backend,
                key,
                RetireKind::Udp {
                    token: 11,
                    incarnation: None,
                    pending_only: false
                }
            )
            .1,
            UdpDecisionCommitResult::Applied
        );
        assert!(backend.conn_state_lookup(&key).unwrap().is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn udp_transition_distinguishes_missing_token_and_state_mismatches() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        assert_eq!(
            backend
                .commit_udp_decision(&key, 1, UdpDecisionTransition::Block)
                .unwrap(),
            UdpDecisionCommitResult::Missing
        );
        seed_staged_flow(&mut backend, &key, 17);
        assert_eq!(
            backend
                .commit_udp_decision(&key, 18, UdpDecisionTransition::Block)
                .unwrap(),
            UdpDecisionCommitResult::TokenMismatch
        );
        let mut newer = backend.conn_state_lookup(&key).unwrap().unwrap();
        newer.state = UdpDecisionState::Proxy as u8;
        backend.udp_conn_state_store(&key, &newer).unwrap();
        assert_eq!(
            backend
                .commit_udp_decision(&key, 17, UdpDecisionTransition::Block)
                .unwrap(),
            UdpDecisionCommitResult::StateMismatch
        );
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
    }

    #[test]
    fn legacy_removal_retires_auxiliaries_and_preserves_native_state() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        backend
            .udp_conn_state_store(
                &key,
                &ConnState {
                    state: UdpDecisionState::None as u8,
                    meta: RoutingMeta {
                        raw: OutboundIndex::UserBase as u64 | ROUTING_META_FLAG_PUBLISHED,
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        backend.routing_handoffs.lock().insert(
            MockEbpfBackend::tuples_key_bytes(&key),
            RoutingHandoffEntry::default(),
        );
        backend
            .redirect_track_store(&RedirectTuple::from_tuples(&key), &RedirectEntry::default())
            .unwrap();

        assert_eq!(
            retire_fixture(
                &mut backend,
                key,
                RetireKind::Udp {
                    token: 0,
                    incarnation: None,
                    pending_only: false
                }
            )
            .1,
            UdpDecisionCommitResult::Applied
        );
        assert!(backend.conn_state_lookup(&key).unwrap().is_none());
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
        assert!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .is_none()
        );

        let terminal_raw =
            OutboundIndex::Direct as u64 | ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD;
        backend
            .udp_conn_state_store(
                &key,
                &ConnState {
                    state: UdpDecisionState::None as u8,
                    meta: RoutingMeta { raw: terminal_raw },
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            retire_fixture(
                &mut backend,
                key,
                RetireKind::Udp {
                    token: 0,
                    incarnation: None,
                    pending_only: false
                }
            )
            .1,
            UdpDecisionCommitResult::Superseded
        );
        assert!(backend.conn_state_lookup(&key).unwrap().is_some());
    }

    #[test]
    fn missing_udp_owner_preserves_auxiliaries() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        seed_staged_flow(&mut backend, &key, 7);
        backend.udp_conn_states.clear();
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::Udp {
                token: 7,
                incarnation: None,
                pending_only: true,
            },
        );
        assert_eq!(counts, RetireCounts::default());
        assert_eq!(outcome, UdpDecisionCommitResult::Missing);
        assert_eq!(
            backend
                .routing_handoff_lookup(&key)
                .unwrap()
                .unwrap()
                .result
                .decision_token,
            7
        );
        assert_eq!(
            backend
                .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                .unwrap()
                .unwrap()
                .decision_token,
            7
        );
    }

    #[test]
    fn pending_retirement_reports_state_delete_and_sequence_survives_cleanup() {
        let mut backend = MockEbpfBackend::new();
        let key = decision_test_key();
        seed_staged_flow(&mut backend, &key, 31);
        let (counts, outcome) = retire_fixture(
            &mut backend,
            key,
            RetireKind::Udp {
                token: 31,
                incarnation: None,
                pending_only: true,
            },
        );
        assert_eq!(outcome, UdpDecisionCommitResult::Applied);
        assert_eq!(counts.conn, 1);
        assert_eq!(counts.redirect, 1);
        assert_eq!(counts.handoff, 1);
        backend.udp_decision_sequence_next = 123;
        futures::executor::block_on(backend.cleanup()).unwrap();
        assert_eq!(backend.udp_decision_sequence_next, 123);
    }

    #[test]
    fn exhausted_sequence_skips_rollback_reachable_generations() {
        let mut backend = MockEbpfBackend::new();
        backend.udp_decision_sequence_next = UDP_DECISION_SEQUENCE_MASK;
        let key = decision_test_key();
        let live_token = udp_decision_token(1, 7).unwrap();
        backend
            .udp_conn_state_store(
                &key,
                &ConnState {
                    state: UdpDecisionState::Proxy as u8,
                    decision_token: live_token,
                    ..Default::default()
                },
            )
            .unwrap();

        assert!(!backend.reset_udp_decision_sequence(0).unwrap());
        assert!(!backend.reset_udp_decision_sequence(1).unwrap());

        assert!(backend.reset_udp_decision_sequence(2).unwrap());
        assert_eq!(
            backend.udp_decision_sequence_status().unwrap(),
            UdpDecisionSequenceStatus {
                next: 0,
                generation: 2,
            }
        );
    }

    #[test]
    fn exhausted_sequence_skips_live_retirement_fence() {
        let mut backend = MockEbpfBackend::new();
        backend.udp_decision_sequence_next = UDP_DECISION_SEQUENCE_MASK;
        let key = decision_test_key();
        backend.retire_fences.insert(
            MockEbpfBackend::tuples_key_bytes(&key),
            RetirementFence {
                owner: 1,
                decision_token: udp_decision_token(1, 7).unwrap(),
                padding: 0,
            },
        );

        assert!(!backend.reset_udp_decision_sequence(1).unwrap());
        backend.retire_fences.clear();
        assert!(backend.reset_udp_decision_sequence(1).unwrap());
    }

    fn routing_plan(tag: u8) -> crate::control::routing_matcher::RoutingPushPlan {
        let rule = honk_config::routing::RoutingRule {
            name: format!("policy-{tag}"),
            condition: honk_config::routing::RoutingCondition {
                domain: vec![format!("policy-{tag}.test")],
                ip: vec![format!("192.0.2.{tag}/32")],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: u32::from(tag),
        };
        let router = crate::routing::Router::new(&[rule], "direct").unwrap();
        crate::control::routing_matcher::RoutingPushPlan::compile(
            &router,
            &HashMap::from([("direct".into(), 0)]),
            honk_config::types::DialMode::Domain,
        )
        .unwrap()
    }

    #[test]
    fn routing_publish_is_atomic_and_root_is_last() {
        let mut backend = MockEbpfBackend::new();
        backend.publish_routing_plan(&routing_plan(1), &[]).unwrap();
        let accepted = backend.routing_snapshot();

        let domain_key = LpmKey {
            prefix_len: 128,
            data: [0, 0, 0xffff0000, 2],
        };
        backend.fail_next_routing_phase(RoutingPushPhase::Root);
        assert!(
            backend
                .publish_routing_plan(&routing_plan(2), &[(domain_key, DomainRouting::default())],)
                .is_err()
        );
        assert_eq!(backend.routing_snapshot(), accepted);

        backend.publish_routing_plan(&routing_plan(3), &[]).unwrap();
        assert!(backend.routing_snapshot().domain.is_empty());
        let replacement = routing_plan(2);
        backend
            .publish_routing_plan(&replacement, &[(domain_key, DomainRouting::default())])
            .unwrap();
        let current = backend.routing_snapshot();
        assert_eq!(current.active_slot, 1);
        assert_eq!(current.plan_fingerprint, replacement.fingerprint);
        assert_eq!(current.domain.len(), 1);
        assert_eq!(current.domain[0].1, [0; ROUTING_BITMAP_WORDS]);
        assert!(matches!(
            backend.routing_publication_order.last(),
            Some(MockRoutingPublicationWrite::Root(1))
        ));
    }

    #[test]
    fn routing_generation_ceiling_rejects_before_staging() {
        let mut backend = MockEbpfBackend::new();
        backend.next_generation = DNS_ROUTE_GENERATION_MAX - 1;
        backend.publish_routing_plan(&routing_plan(1), &[]).unwrap();
        let accepted = backend.routing_snapshot();
        let writes = backend.routing_publication_order.clone();

        assert!(backend.publish_routing_plan(&routing_plan(2), &[]).is_err());
        assert_eq!(
            backend.routing_policy_generation(),
            DNS_ROUTE_GENERATION_MAX
        );
        assert_eq!(backend.routing_snapshot(), accepted);
        assert_eq!(backend.routing_publication_order, writes);
    }

    #[test]
    fn active_domain_zero_is_present_until_removed() {
        let mut backend = MockEbpfBackend::new();
        backend.publish_routing_plan(&routing_plan(1), &[]).unwrap();
        let key = LpmKey {
            prefix_len: 128,
            data: [0, 0, 0xffff0000, 3],
        };
        backend
            .set_domain_ip_bitmap(&key, &DomainRouting::default())
            .unwrap();
        assert_eq!(backend.routing_snapshot().domain.len(), 1);
        backend.remove_domain_ip_bitmap(&key).unwrap();
        assert!(backend.routing_snapshot().domain.is_empty());
    }

    #[test]
    fn test_redirect_track_crud() {
        let mut backend = MockEbpfBackend::new();

        let key = RedirectTuple {
            src_ip: In6Addr::default(),
            dst_ip: In6Addr::default(),
            ..Default::default()
        };
        let entry = RedirectEntry {
            last_seen_ns: 1111111111,
            dmac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            smac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            from_wan: 0,
            ifindex: 2,
            ..Default::default()
        };

        assert!(backend.redirect_track_lookup(&key).unwrap().is_none());

        backend.redirect_track_store(&key, &entry).unwrap();
        let found = backend.redirect_track_lookup(&key).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().last_seen_ns, 1111111111);

        let tuple = TuplesKey {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            src_port: key.src_port,
            dst_port: key.dst_port,
            l4proto: key.l4proto,
            padding: [0; 3],
        };
        assert_eq!(
            retire_fixture(
                &mut backend,
                tuple,
                RetireKind::ExpiredRedirect {
                    expected: &entry,
                    expired_before_ns: entry.last_seen_ns
                }
            )
            .0
            .redirect,
            1
        );
        assert!(backend.redirect_track_lookup(&key).unwrap().is_none());
    }

    #[test]
    fn test_routing_handoff_lookup_and_retirement() {
        let mut backend = MockEbpfBackend::new();

        let key = TuplesKey {
            src_ip: In6Addr::default(),
            dst_ip: In6Addr::default(),
            src_port: 3000,
            dst_port: 80,
            l4proto: 6,
            padding: [0; 3],
        };

        let entry = RoutingHandoffEntry {
            last_seen_ns: 0,
            result: RoutingResult {
                mark: 1234,
                outbound: 5,
                ..Default::default()
            },
            routing_generation: 0,
            ..Default::default()
        };
        backend
            .routing_handoffs
            .lock()
            .insert(MockEbpfBackend::tuples_key_bytes(&key), entry);

        let found = backend.routing_handoff_lookup(&key).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().result.mark, 1234);

        assert!(backend.routing_handoff_lookup(&key).unwrap().is_some());
        assert_eq!(
            retire_fixture(
                &mut backend,
                key,
                RetireKind::ExpiredHandoff {
                    expected: &entry,
                    expired_before_ns: 0
                }
            )
            .0
            .handoff,
            1
        );
        assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
    }

    #[test]
    fn test_get_bpf_stats() {
        let mut backend = MockEbpfBackend::new();

        assert!(backend.get_bpf_stats(0).unwrap().is_none());
        assert!(backend.get_bpf_stats(42).unwrap().is_none());

        backend.bpf_stats.insert(0, 100);
        backend.bpf_stats.insert(1, 250);
        backend.bpf_stats.insert(99, 999);

        assert_eq!(backend.get_bpf_stats(0).unwrap(), Some(100));
        assert_eq!(backend.get_bpf_stats(1).unwrap(), Some(250));
        assert_eq!(backend.get_bpf_stats(99).unwrap(), Some(999));
        assert!(backend.get_bpf_stats(50).unwrap().is_none());
    }

    #[test]
    fn trace_capture_exhaustion_and_cleanup_never_reuse_ids() {
        let mut backend = MockEbpfBackend::new();
        let mut witness = KernelRouteWitness::default();
        assert_eq!(backend.capture_route_witness(witness), 0);
        witness.output.flags = ROUTE_TRACE_ENABLED;
        let first = backend.capture_route_witness(witness);
        futures::executor::block_on(backend.cleanup()).unwrap();
        assert!(backend.capture_route_witness(witness) > first);
        backend.next_trace_id = ROUTE_TRACE_LOST - 2;
        assert_eq!(backend.capture_route_witness(witness), ROUTE_TRACE_LOST - 1);
        backend.route_witnesses.clear();
        assert_eq!(backend.capture_route_witness(witness), ROUTE_TRACE_LOST);
        assert_eq!(backend.capture_route_witness(witness), ROUTE_TRACE_LOST);
        assert!(backend.route_witnesses.is_empty());
    }

    #[test]
    fn test_cleanup_clears_all_maps() {
        let mut backend = MockEbpfBackend::new();
        backend
            .tcp_conn_state_store(&TuplesKey::default(), &ConnState::default())
            .unwrap();
        backend
            .udp_conn_state_store(&TuplesKey::default(), &ConnState::default())
            .unwrap();
        backend
            .redirect_track_store(&RedirectTuple::default(), &RedirectEntry::default())
            .unwrap();
        backend.set_outbound_alive(1, 0, 4, true).unwrap();
        backend.bpf_stats.insert(0, 999);

        futures::executor::block_on(backend.cleanup()).unwrap();

        assert!(backend.tcp_conn_states.is_empty());
        assert!(backend.udp_conn_states.is_empty());
        assert!(backend.redirect_tracks.is_empty());
        assert!(backend.routing_handoffs.lock().is_empty());
        assert!(backend.outbound_alive.is_empty());
        assert!(backend.bpf_stats.is_empty());
    }
}
