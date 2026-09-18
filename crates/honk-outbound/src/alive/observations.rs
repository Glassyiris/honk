use super::{AliveDialerSet, IpVersion, ProbeDomain, RegisteredNode};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Timing captured at the successful exchange, before retries or cleanup.
#[derive(Debug, Clone, Copy)]
pub struct ProbeMeasurement {
    pub latency: Duration,
    pub observed_at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthPurpose {
    Data,
    Dns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthMeasurement {
    TcpConnect,
    HttpHeaders,
    DnsRoundTrip,
    QuicHandshake,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthWarmth {
    Cold,
    Warm,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Unavailable,
}

/// One completed probe, independent of routing hysteresis and latency ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeHealthObservation {
    pub transport: HealthTransport,
    pub purpose: HealthPurpose,
    pub measurement: HealthMeasurement,
    pub ip_version: IpVersion,
    pub warmth: HealthWarmth,
    pub sample_source: &'static str,
    pub state: HealthState,
    pub latency: Option<Duration>,
    pub observed_at: SystemTime,
    pub error: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct NativeGroupProbeContext {
    pub group_id: Uuid,
    pub member_id: Uuid,
}

/// Registration and group-target identity captured before a native probe starts.
#[derive(Debug, Clone)]
pub struct NativeProbeTicket {
    node: Uuid,
    registration: Option<Arc<RegisteredNode>>,
    group_epoch: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeGroupHealthObservation {
    pub group_id: Uuid,
    pub member_id: Uuid,
    pub node_id: Uuid,
    pub observation: NativeHealthObservation,
}

pub struct UrlProbeMember {
    pub tag: String,
    pub leaf: Uuid,
    pub native: Option<NativeGroupProbeContext>,
}

#[derive(Default)]
pub(super) struct NativeObservations {
    pub nodes: HashMap<Uuid, Vec<NativeHealthObservation>>,
    pub groups: VecDeque<NativeGroupHealthObservation>,
    epoch: Option<Uuid>,
}

impl NativeHealthObservation {
    pub fn probe(
        domain: ProbeDomain,
        measurement: HealthMeasurement,
        ip_version: IpVersion,
        latency: Option<Duration>,
        observed_at: SystemTime,
    ) -> Self {
        Self {
            transport: if domain == ProbeDomain::Tcp {
                HealthTransport::Tcp
            } else {
                HealthTransport::Udp
            },
            purpose: if domain == ProbeDomain::DnsUdp {
                HealthPurpose::Dns
            } else {
                HealthPurpose::Data
            },
            measurement,
            ip_version,
            warmth: if measurement == HealthMeasurement::TcpConnect {
                HealthWarmth::Cold
            } else {
                HealthWarmth::Unknown
            },
            sample_source: "probe",
            state: if latency.is_some() {
                HealthState::Healthy
            } else {
                HealthState::Unavailable
            },
            latency,
            observed_at,
            error: latency.is_none().then_some("probe_failed"),
        }
    }

    fn same_key(&self, other: &Self) -> bool {
        self.transport == other.transport
            && self.purpose == other.purpose
            && self.measurement == other.measurement
            && self.ip_version == other.ip_version
            && self.warmth == other.warmth
    }
}

impl AliveDialerSet {
    /// Allocate retention only for an enabled native listener.
    pub fn enable_native_observations(&self) {
        self.native_observations
            .write()
            .get_or_insert_with(|| NativeObservations {
                epoch: Some(Uuid::new_v4()),
                ..Default::default()
            });
    }

    pub fn native_probe_ticket(&self, node: Uuid) -> NativeProbeTicket {
        let registered = self.registered.read();
        NativeProbeTicket {
            node,
            registration: registered.get(&node).cloned(),
            group_epoch: self.native_group_epoch(),
        }
    }

    /// Retain the exact typed sample, without changing legacy liveness or latency.
    /// All native probes require the captured target epoch to remain current.
    pub fn complete_native_probe(
        &self,
        ticket: &NativeProbeTicket,
        context: Option<NativeGroupProbeContext>,
        observation: NativeHealthObservation,
    ) -> bool {
        let Some(epoch) = ticket.group_epoch else {
            return false;
        };
        match context {
            Some(context) => self.retain_native_group_observation(
                ticket.node,
                ticket.registration.as_ref(),
                context,
                epoch,
                observation,
            ),
            None => self.retain_native_observation(
                ticket.node,
                ticket.registration.as_ref(),
                Some(epoch),
                observation,
            ),
        }
    }

    /// Read completed global checks only; custom group targets remain separate.
    pub fn native_observations(&self, node: Uuid) -> Vec<NativeHealthObservation> {
        self.native_observations
            .read()
            .as_ref()
            .and_then(|observations| observations.nodes.get(&node))
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn record_native_observation(
        &self,
        node: Uuid,
        registration: Option<&Arc<RegisteredNode>>,
        observation: NativeHealthObservation,
    ) {
        self.retain_native_observation(node, registration, None, observation);
    }

    fn retain_native_observation(
        &self,
        node: Uuid,
        registration: Option<&Arc<RegisteredNode>>,
        required_epoch: Option<Uuid>,
        observation: NativeHealthObservation,
    ) -> bool {
        let registered = self.registered.read();
        if !Self::same_registration(registered.get(&node), registration)
            || (registration.is_none() && node != honk_config::config::DIRECT_NODE_ID)
        {
            return false;
        }
        let mut retained = self.native_observations.write();
        let Some(retained) = retained.as_mut() else {
            return false;
        };
        if required_epoch.is_some_and(|epoch| retained.epoch != Some(epoch)) {
            return false;
        }
        // The enum-only key bounds retention independently of probe targets.
        let observations = retained.nodes.entry(node).or_default();
        if let Some(previous) = observations
            .iter_mut()
            .find(|old| old.same_key(&observation))
        {
            if observation.observed_at < previous.observed_at {
                return false;
            }
            *previous = observation;
        } else {
            observations.push(observation);
        }
        true
    }

    pub fn native_group_observations(&self, group: Uuid) -> Vec<NativeGroupHealthObservation> {
        self.native_observations
            .read()
            .as_ref()
            .map_or_else(Vec::new, |retained| {
                retained
                    .groups
                    .iter()
                    .filter(|sample| sample.group_id == group)
                    .copied()
                    .collect()
            })
    }

    pub(super) fn native_group_epoch(&self) -> Option<Uuid> {
        self.native_observations
            .read()
            .as_ref()
            .and_then(|retained| retained.epoch)
    }

    /// Invalidate at accepted configuration publication, before asynchronous
    /// cleanup can leave old probe targets beside the newly published catalog.
    /// Capture resumes only after `sync_group_check_urls` installs accepted targets.
    pub fn invalidate_native_group_observations(&self) {
        if let Some(retained) = self.native_observations.write().as_mut() {
            retained.epoch = None;
            retained.groups.clear();
        }
    }

    pub(super) fn reset_native_group_observations(&self) {
        if let Some(retained) = self.native_observations.write().as_mut() {
            retained.epoch = Some(Uuid::new_v4());
            retained.groups.clear();
        }
    }

    pub(super) fn advance_native_probe_epoch(&self) {
        if let Some(retained) = self.native_observations.write().as_mut()
            && retained.epoch.is_some()
        {
            retained.epoch = Some(Uuid::new_v4());
        }
    }

    pub(super) fn record_native_group_observation(
        &self,
        node: Uuid,
        registration: Option<&Arc<RegisteredNode>>,
        context: NativeGroupProbeContext,
        epoch: Uuid,
        observation: NativeHealthObservation,
    ) {
        self.retain_native_group_observation(node, registration, context, epoch, observation);
    }

    fn retain_native_group_observation(
        &self,
        node: Uuid,
        registration: Option<&Arc<RegisteredNode>>,
        context: NativeGroupProbeContext,
        epoch: Uuid,
        observation: NativeHealthObservation,
    ) -> bool {
        let registered = self.registered.read();
        if !Self::same_registration(registered.get(&node), registration)
            || (registration.is_none() && node != honk_config::config::DIRECT_NODE_ID)
        {
            return false;
        }
        let mut retained = self.native_observations.write();
        let Some(retained) = retained
            .as_mut()
            .filter(|retained| retained.epoch == Some(epoch))
        else {
            return false;
        };
        let sample = NativeGroupHealthObservation {
            group_id: context.group_id,
            member_id: context.member_id,
            node_id: node,
            observation,
        };
        // ponytail: at most 4096 fixed-size group tuples; add an index only if probe cost warrants it.
        if let Some(old) = retained.groups.iter_mut().find(|old| {
            old.group_id == context.group_id
                && old.member_id == context.member_id
                && old.observation.same_key(&observation)
        }) {
            if observation.observed_at < old.observation.observed_at {
                return false;
            }
            *old = sample;
        } else {
            if retained.groups.len() == 4096 {
                retained.groups.pop_front();
            }
            retained.groups.push_back(sample);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NativeHealthObservation {
        NativeHealthObservation::probe(
            ProbeDomain::DnsUdp,
            HealthMeasurement::DnsRoundTrip,
            IpVersion::V4,
            Some(Duration::from_millis(1)),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        )
    }

    #[test]
    fn native_ticket_rejects_missing_removed_and_replaced_registration() {
        let set = AliveDialerSet::new();
        let node = Uuid::from_u128(1);
        set.enable_native_observations();
        let missing = set.native_probe_ticket(node);
        assert!(!set.complete_native_probe(&missing, None, sample()));
        set.register_node(node, "node".into(), "127.0.0.1:1".into());
        assert!(!set.complete_native_probe(&missing, None, sample()));
        let ticket = set.native_probe_ticket(node);
        assert!(set.complete_native_probe(&ticket, None, sample()));
        set.register_node(node, "node".into(), "127.0.0.1:1".into());
        let context = NativeGroupProbeContext {
            group_id: Uuid::from_u128(2),
            member_id: node,
        };
        assert!(!set.complete_native_probe(&ticket, None, sample()));
        assert!(!set.complete_native_probe(&ticket, Some(context), sample()));
        let replacement = set.native_probe_ticket(node);
        assert!(set.complete_native_probe(&replacement, Some(context), sample()));
        set.remove_node(node);
        assert!(!set.complete_native_probe(&replacement, None, sample()));
        assert!(!set.complete_native_probe(&replacement, Some(context), sample()));
        assert!(set.native_observations(node).is_empty());
        assert!(set.native_group_observations(context.group_id).is_empty());
    }

    #[test]
    fn native_ticket_rejects_invalidated_group_epoch_and_older_samples() {
        let set = AliveDialerSet::new();
        let node = Uuid::from_u128(1);
        set.register_node(node, "node".into(), "127.0.0.1:1".into());
        let disabled = set.native_probe_ticket(node);
        assert!(!set.complete_native_probe(&disabled, None, sample()));
        set.enable_native_observations();
        let context = NativeGroupProbeContext {
            group_id: Uuid::from_u128(2),
            member_id: node,
        };
        assert!(!set.complete_native_probe(&disabled, Some(context), sample()));
        let ticket = set.native_probe_ticket(node);
        assert!(set.complete_native_probe(&ticket, Some(context), sample()));
        set.invalidate_native_group_observations();
        let invalidated = set.native_probe_ticket(node);
        assert!(!set.complete_native_probe(&ticket, Some(context), sample()));
        assert!(!set.complete_native_probe(&invalidated, Some(context), sample()));
        set.sync_group_check_urls(&[]);
        assert!(!set.complete_native_probe(&ticket, Some(context), sample()));
        assert!(!set.complete_native_probe(&invalidated, Some(context), sample()));
        assert!(set.native_group_observations(context.group_id).is_empty());
        let current = set.native_probe_ticket(node);
        assert!(set.complete_native_probe(&current, Some(context), sample()));
        assert!(set.complete_native_probe(&current, None, sample()));
        let older = NativeHealthObservation {
            observed_at: SystemTime::UNIX_EPOCH,
            ..sample()
        };
        assert!(!set.complete_native_probe(&current, Some(context), older));
        assert!(!set.complete_native_probe(&current, None, older));
        assert_eq!(set.native_observations(node), [sample()]);
        assert_eq!(
            set.native_group_observations(context.group_id)[0].observation,
            sample()
        );
    }

    #[test]
    fn native_global_ticket_rejects_reloaded_targets_without_changing_periodic_writes() {
        for node in [Uuid::from_u128(1), honk_config::config::DIRECT_NODE_ID] {
            let set = AliveDialerSet::new();
            if node != honk_config::config::DIRECT_NODE_ID {
                set.register_node(node, "node".into(), "127.0.0.1:1".into());
            }
            let disabled = set.native_probe_ticket(node);
            set.enable_native_observations();
            assert!(!set.complete_native_probe(&disabled, None, sample()));
            let ticket = set.native_probe_ticket(node);
            assert!(set.complete_native_probe(&ticket, None, sample()));
            set.invalidate_native_group_observations();
            let invalidated = set.native_probe_ticket(node);
            let newer = NativeHealthObservation {
                observed_at: sample().observed_at + Duration::from_secs(1),
                ..sample()
            };
            assert!(!set.complete_native_probe(&ticket, None, newer));
            assert!(!set.complete_native_probe(&invalidated, None, newer));
            assert_eq!(set.native_observations(node), [sample()]);
            let registration = set.registered.read().get(&node).cloned();
            set.record_native_observation(node, registration.as_ref(), newer);
            assert_eq!(set.native_observations(node), [newer]);
            set.sync_group_check_urls(&[]);
            assert!(!set.complete_native_probe(&ticket, None, newer));
            assert!(!set.complete_native_probe(&invalidated, None, newer));
            let current = set.native_probe_ticket(node);
            assert!(set.complete_native_probe(&current, None, newer));
        }
    }

    #[test]
    fn native_completion_keeps_typed_keys_out_of_legacy_latency() {
        let set = AliveDialerSet::new();
        let node = Uuid::from_u128(1);
        set.enable_native_observations();
        set.register_node(node, "node".into(), "127.0.0.1:1".into());
        let ticket = set.native_probe_ticket(node);
        let context = NativeGroupProbeContext {
            group_id: Uuid::from_u128(2),
            member_id: node,
        };
        let samples = [
            sample(),
            NativeHealthObservation {
                transport: HealthTransport::Tcp,
                ..sample()
            },
            NativeHealthObservation {
                purpose: HealthPurpose::Data,
                ..sample()
            },
            NativeHealthObservation {
                warmth: HealthWarmth::Warm,
                ..sample()
            },
            NativeHealthObservation::probe(
                ProbeDomain::Tcp,
                HealthMeasurement::TcpConnect,
                IpVersion::V4,
                Some(Duration::ZERO),
                sample().observed_at,
            ),
            NativeHealthObservation::probe(
                ProbeDomain::Tcp,
                HealthMeasurement::HttpHeaders,
                IpVersion::V4,
                Some(Duration::from_millis(2)),
                sample().observed_at,
            ),
        ];
        for observation in samples {
            assert!(set.complete_native_probe(&ticket, None, observation));
            assert!(set.complete_native_probe(&ticket, Some(context), observation));
        }
        assert_eq!(set.native_observations(node), samples);
        let retained = set.native_group_observations(context.group_id);
        assert_eq!(
            retained
                .iter()
                .map(|sample| sample.observation)
                .collect::<Vec<_>>(),
            samples
        );
        for domain in [ProbeDomain::Tcp, ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
            assert_eq!(set.get_last_latency(node, domain, IpVersion::V4), None);
        }
    }

    #[test]
    fn native_direct_completion_preserves_duplicate_member_associations() {
        let set = AliveDialerSet::new();
        set.enable_native_observations();
        let node = honk_config::config::DIRECT_NODE_ID;
        let ticket = set.native_probe_ticket(node);
        let group_id = Uuid::from_u128(1);
        assert!(set.complete_native_probe(&ticket, None, sample()));
        for member_id in [Uuid::from_u128(2), Uuid::from_u128(3)] {
            let context = NativeGroupProbeContext {
                group_id,
                member_id,
            };
            assert!(set.complete_native_probe(&ticket, Some(context), sample()));
        }
        let retained = set.native_group_observations(group_id);
        assert_eq!(
            retained
                .iter()
                .map(|sample| sample.member_id)
                .collect::<Vec<_>>(),
            [Uuid::from_u128(2), Uuid::from_u128(3)]
        );
        assert!(retained.iter().all(|sample| sample.node_id == node));
        let block = set.native_probe_ticket(honk_config::config::BLOCK_NODE_ID);
        assert!(!set.complete_native_probe(&block, None, sample()));
    }
}
