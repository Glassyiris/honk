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
        let registered = self.registered.read();
        if !Self::same_registration(registered.get(&node), registration)
            || (registration.is_none() && node != honk_config::config::DIRECT_NODE_ID)
        {
            return;
        }
        let mut retained = self.native_observations.write();
        let Some(retained) = retained.as_mut() else {
            return;
        };
        // The enum-only key bounds each node to 80 possible tuples, independent of URLs.
        let observations = retained.nodes.entry(node).or_default();
        if let Some(previous) = observations
            .iter_mut()
            .find(|old| old.same_key(&observation))
        {
            if observation.observed_at >= previous.observed_at {
                *previous = observation;
            }
        } else {
            observations.push(observation);
        }
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

    pub(super) fn record_native_group_observation(
        &self,
        node: Uuid,
        registration: Option<&Arc<RegisteredNode>>,
        context: NativeGroupProbeContext,
        epoch: Uuid,
        observation: NativeHealthObservation,
    ) {
        let registered = self.registered.read();
        if registration.is_none() || !Self::same_registration(registered.get(&node), registration) {
            return;
        }
        let mut retained = self.native_observations.write();
        let Some(retained) = retained
            .as_mut()
            .filter(|retained| retained.epoch == Some(epoch))
        else {
            return;
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
            if observation.observed_at >= old.observation.observed_at {
                *old = sample;
            }
        } else {
            if retained.groups.len() == 4096 {
                retained.groups.pop_front();
            }
            retained.groups.push_back(sample);
        }
    }
}
