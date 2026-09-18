//! Daemon-owned, bounded typed probes over captured configuration and runtime owners.

use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use honk_config::{Config, experimental::NativeApiConfig, node::Node};
use honk_outbound::{
    alive::{
        HealthMeasurement, HealthPurpose, HealthState, HealthTransport, HealthWarmth, IpVersion,
        NativeGroupProbeContext, NativeHealthObservation, NativeProbeTicket, ProbeDomain,
        ProbeMeasurement,
    },
    group::{GroupManager, NativeGroupMember, SelectionNetwork},
    runtime::OutboundRuntimeRegistry,
};
use ipnet::IpNet;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{Notify, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use uuid::Uuid;

use super::{
    ApiError, ErrorCode, NativeState,
    catalog::CatalogIdentity,
    operations::{OperationKind, OperationResult, OperationStore, Reservation},
    parse_query,
    security::RequestRate,
    timestamp,
    types::RequestId,
};

#[cfg(test)]
mod tests;
mod wire;

const MAX_MEMBERS: usize = 64;
const MAX_RESULTS: usize = 256;
const MAX_ACTIVE: usize = 4;
const MAX_QUEUED: usize = 16;
const DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    TcpConnect,
    Http,
    Dns,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
enum Family {
    Ipv4,
    Ipv6,
}
impl Family {
    fn ip(self) -> IpVersion {
        match self {
            Self::Ipv4 => IpVersion::V4,
            Self::Ipv6 => IpVersion::V6,
        }
    }
    fn matches(self, ip: IpAddr) -> bool {
        ip.is_ipv4() == (self == Self::Ipv4)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum RequestedFamily {
    Ipv4,
    Ipv6,
    Any,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Warmth {
    Cold,
    Warm,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Target {
    Node { node_id: String },
    Group { group_id: String },
}
impl Target {
    fn key(&self) -> String {
        match self {
            Self::Node { node_id } => format!("node:{node_id}"),
            Self::Group { group_id } => format!("group:{group_id}"),
        }
    }
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Members {
    Scope(MemberScope),
    Ids(Vec<String>),
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum MemberScope {
    Direct,
    Leaves,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRequest {
    target: Target,
    kind: Kind,
    purpose: Purpose,
    transport: Vec<Transport>,
    ip_version: RequestedFamily,
    warmth: Warmth,
    #[serde(default, deserialize_with = "present_members")]
    members: Option<Members>,
}
fn present_members<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Members>, D::Error> {
    Members::deserialize(deserializer).map(Some)
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Purpose {
    Data,
    Dns,
}
#[derive(Debug, Serialize)]
pub(crate) struct ProbeResult {
    target: Target,
    selection_changed: TransportMap<bool>,
    selection_before: TransportMap<Option<String>>,
    selection_after: TransportMap<Option<String>>,
    results: Vec<ResultRow>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct TransportMap<T> {
    tcp: T,
    udp: T,
}
#[derive(Debug, Serialize)]
struct ResultRow {
    member_id: String,
    resolved_leaf_node_id: Option<String>,
    kind: Kind,
    purpose: Purpose,
    transport: Transport,
    ip_version: Family,
    warmth: &'static str,
    state: &'static str,
    latency_ms: Option<f64>,
    health_updated: bool,
    error: Option<&'static str>,
    observed_at: String,
}
struct Attempt {
    node: Node,
    ticket: NativeProbeTicket,
    transport: Transport,
    family: Family,
    rows: Vec<usize>,
    addr: Option<SocketAddr>,
    server: Option<IpAddr>,
}
struct Plan {
    request: ProbeRequest,
    config: Arc<Config>,
    manager: Arc<GroupManager>,
    identity: Arc<CatalogIdentity>,
    registry: Arc<OutboundRuntimeRegistry>,
    dns: DnsPin,
    group: Option<String>,
    http: Option<http::Request<()>>,
    destination: Option<(String, u16)>,
    result: ProbeResult,
    attempts: Vec<Attempt>,
}
enum DnsPin {
    Runtime(crate::dns::runtime::RuntimeLease),
    Standalone(Arc<crate::dns::forwarder::DnsForwarder>),
}
struct Job {
    reservation: Reservation,
    plan: Plan,
    deadline: Instant,
}
struct RunningJob<'a> {
    service: &'a ProbeService,
    target: String,
    id: String,
}
impl Drop for RunningJob<'_> {
    fn drop(&mut self) {
        self.service.targets.lock().remove(&self.target);
        self.service.operations.fail(
            &self.id,
            "probe_interrupted",
            "Probe worker did not complete.",
            None,
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProbeLifecycleError {
    #[error("Probe worker is unavailable")]
    Unavailable,
    #[error("Probe worker transition conflicts with its current state")]
    Conflict,
    #[error("Probe worker cleanup failed")]
    CleanupFailed,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerState {
    NotStarted,
    Running,
    Transitioning,
    Paused,
    Faulted,
    Stopped,
}
enum Command {
    Pause(oneshot::Sender<Result<(), ProbeLifecycleError>>),
    Resume(oneshot::Sender<Result<(), ProbeLifecycleError>>),
}
struct Gate {
    state: WorkerState,
    requests: usize,
    cancel: watch::Sender<bool>,
    engine: Option<std::sync::Weak<NativeState>>,
}
struct RequestGuard<'a> {
    service: &'a ProbeService,
    cancel: Option<watch::Receiver<bool>>,
}
impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        if self.cancel.is_some() {
            let mut gate = self.service.gate.lock();
            gate.requests -= 1;
            if gate.requests == 0 {
                self.service.requests_drained.notify_one();
            }
        }
    }
}

pub(crate) struct ProbeService {
    operations: Arc<OperationStore>,
    policy: Policy,
    rate: RequestRate,
    sender: mpsc::Sender<Job>,
    receiver: Mutex<Option<(mpsc::Receiver<Job>, mpsc::Receiver<Command>)>>,
    commands: mpsc::Sender<Command>,
    targets: Mutex<HashSet<String>>,
    gate: Mutex<Gate>,
    requests_drained: Notify,
}
struct Policy {
    allowed: Vec<IpNet>,
    ports: Vec<u16>,
    restricted: Vec<IpNet>,
}
impl Policy {
    fn new(config: &NativeApiConfig) -> Self {
        Self {
            allowed: config
                .probe_allowed_cidrs
                .iter()
                .map(|value| value.parse().expect("validated probe CIDR"))
                .collect(),
            ports: config.probe_allowed_ports.clone(),
            restricted: [
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.0.0.0/24",
                "192.0.2.0/24",
                "192.88.99.0/24",
                "192.168.0.0/16",
                "198.18.0.0/15",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "224.0.0.0/4",
                "240.0.0.0/4",
                "2001::/23",
                "2001:db8::/32",
                "2002::/16",
                "3fff::/20",
            ]
            .iter()
            .map(|value| value.parse().unwrap())
            .collect(),
        }
    }
    fn address(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        let restricted = self.restricted.iter().any(|net| net.contains(&ip))
            || match ip {
                IpAddr::V4(_) => false,
                IpAddr::V6(ip) => ip.segments()[0] & 0xe000 != 0x2000,
            };
        !restricted || self.allowed.iter().any(|net| net.contains(&ip))
    }
    fn port(&self, kind: Kind, port: u16, https: bool) -> bool {
        port != 0
            && (kind == Kind::TcpConnect
                || self.ports.contains(&port)
                || port
                    == if kind == Kind::Dns {
                        53
                    } else if https {
                        443
                    } else {
                        80
                    })
    }
}

impl ProbeService {
    pub(crate) fn new(config: &NativeApiConfig, operations: Arc<OperationStore>) -> Self {
        let (sender, receiver) = mpsc::channel(MAX_QUEUED);
        let (commands, command_receiver) = mpsc::channel(1);
        let (cancel, _) = watch::channel(false);
        Self {
            operations,
            policy: Policy::new(config),
            rate: RequestRate::new(),
            sender,
            receiver: Mutex::new(Some((receiver, command_receiver))),
            commands,
            targets: Mutex::new(HashSet::new()),
            gate: Mutex::new(Gate {
                state: WorkerState::NotStarted,
                requests: 0,
                cancel,
                engine: None,
            }),
            requests_drained: Notify::new(),
        }
    }
    pub(crate) fn running(&self) -> bool {
        let gate = self.gate.lock();
        gate.state == WorkerState::Running
            && gate
                .engine
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|state| state.require_running().is_ok())
    }
    pub(crate) fn paused(&self) -> bool {
        self.gate.lock().state == WorkerState::Paused
    }
    pub(crate) async fn pause(&self) -> Result<(), ProbeLifecycleError> {
        let (reply, result) = oneshot::channel();
        {
            let mut gate = self.gate.lock();
            match gate.state {
                WorkerState::Running => {}
                WorkerState::NotStarted | WorkerState::Stopped => {
                    return Err(ProbeLifecycleError::Unavailable);
                }
                WorkerState::Faulted => return Err(ProbeLifecycleError::CleanupFailed),
                _ => return Err(ProbeLifecycleError::Conflict),
            }
            let permit = self
                .commands
                .try_reserve()
                .map_err(|_| ProbeLifecycleError::Unavailable)?;
            gate.state = WorkerState::Transitioning;
            gate.cancel.send_replace(true);
            permit.send(Command::Pause(reply));
        }
        result
            .await
            .unwrap_or(Err(ProbeLifecycleError::Unavailable))
    }
    pub(crate) async fn resume(&self) -> Result<(), ProbeLifecycleError> {
        let (reply, result) = oneshot::channel();
        {
            let mut gate = self.gate.lock();
            match gate.state {
                WorkerState::Paused => {}
                WorkerState::NotStarted | WorkerState::Stopped => {
                    return Err(ProbeLifecycleError::Unavailable);
                }
                WorkerState::Faulted => return Err(ProbeLifecycleError::CleanupFailed),
                _ => return Err(ProbeLifecycleError::Conflict),
            }
            let permit = self
                .commands
                .try_reserve()
                .map_err(|_| ProbeLifecycleError::Unavailable)?;
            gate.state = WorkerState::Transitioning;
            permit.send(Command::Resume(reply));
        }
        result
            .await
            .unwrap_or(Err(ProbeLifecycleError::Unavailable))
    }
    fn request(&self) -> RequestGuard<'_> {
        let mut gate = self.gate.lock();
        let cancel = if gate.state == WorkerState::Running {
            gate.requests += 1;
            Some(gate.cancel.subscribe())
        } else {
            None
        };
        RequestGuard {
            service: self,
            cancel,
        }
    }
    async fn drain_requests(&self) {
        while self.gate.lock().requests != 0 {
            self.requests_drained.notified().await;
        }
    }
    pub(crate) fn capability(&self) -> Value {
        json!({"available": self.running(), "targets":["node","group"], "kinds":["tcp_connect","http","dns"], "purposes":["data","dns"], "transports":["tcp","udp"], "ip_versions":["ipv4","ipv6"], "limits":{"max_members_per_job":MAX_MEMBERS,"max_results_per_job":MAX_RESULTS,"max_active_jobs":MAX_ACTIVE,"max_queued_jobs":MAX_QUEUED,"max_concurrent_per_target":1,"job_timeout_ms":30000,"per_principal_requests_per_minute":30,"global_requests_per_minute":30}})
    }
    pub(crate) fn start(
        self: &Arc<Self>,
        state: Arc<NativeState>,
        mut stop: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        let (mut receiver, mut commands) = self
            .receiver
            .lock()
            .take()
            .expect("probe service starts once");
        {
            let mut gate = self.gate.lock();
            gate.state = WorkerState::Running;
            gate.engine = Some(Arc::downgrade(&state));
        }
        let owner = Arc::clone(self);
        tokio::spawn(async move {
            let mut jobs = JoinSet::new();
            let mut clean = true;
            loop {
                if *stop.borrow() {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = stop.changed() => break,
                    command = commands.recv() => match command {
                        Some(Command::Pause(reply)) => {
                            while let Ok(job) = receiver.try_recv() {
                                owner.operations.reject(&job.reservation.id, paused());
                                owner.targets.lock().remove(&job.plan.request.target.key());
                            }
                            owner.drain_requests().await;
                            while let Some(result) = jobs.join_next().await { clean &= result.is_ok(); }
                            owner.gate.lock().state = if clean { WorkerState::Paused } else { WorkerState::Faulted };
                            let _ = reply.send(if clean { Ok(()) } else { Err(ProbeLifecycleError::CleanupFailed) });
                        }
                        Some(Command::Resume(reply)) => {
                            let result = if clean {
                                let mut gate = owner.gate.lock();
                                gate.cancel = watch::channel(false).0;
                                gate.state = WorkerState::Running;
                                Ok(())
                            } else {
                                owner.gate.lock().state = WorkerState::Faulted;
                                Err(ProbeLifecycleError::CleanupFailed)
                            };
                            let _ = reply.send(result);
                        }
                        None => break,
                    },
                    completed = jobs.join_next(), if !jobs.is_empty() => { clean &= completed.is_some_and(|result| result.is_ok()); },
                    job = receiver.recv(), if jobs.len() < MAX_ACTIVE => {
                        let Some(job) = job else { break; };
                        let gate = owner.gate.lock();
                        if gate.state != WorkerState::Running {
                            owner.operations.reject(&job.reservation.id, paused());
                            owner.targets.lock().remove(&job.plan.request.target.key());
                            continue;
                        }
                        let cancel = gate.cancel.subscribe();
                        let owner = Arc::clone(&owner);
                        let state = Arc::clone(&state);
                        jobs.spawn(async move { owner.run_job(&state, job, cancel).await; });
                    }
                }
            }
            {
                let mut gate = owner.gate.lock();
                gate.state = WorkerState::Stopped;
                gate.cancel.send_replace(true);
            }
            commands.close();
            receiver.close();
            while let Some(job) = receiver.recv().await {
                owner.operations.reject(&job.reservation.id, unavailable());
                owner.targets.lock().remove(&job.plan.request.target.key());
            }
            owner.drain_requests().await;
            while jobs.join_next().await.is_some() {}
        })
    }
    fn enqueue(&self, job: Job) -> Result<(), ApiError> {
        let gate = self.gate.lock();
        let mut targets = self.targets.lock();
        let reject = |error: ApiError| {
            self.operations.reject(&job.reservation.id, error.clone());
            error
        };
        if gate.state != WorkerState::Running {
            return Err(reject(
                if matches!(gate.state, WorkerState::Paused | WorkerState::Transitioning) {
                    paused()
                } else {
                    unavailable()
                },
            ));
        }
        let key = job.plan.request.target.key();
        if targets.contains(&key) {
            return Err(reject(
                ApiError::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    ErrorCode::RateLimited,
                    "A probe for this target is already admitted.",
                    None,
                )
                .with_retry_after(1),
            ));
        }
        let permit = self
            .sender
            .try_reserve()
            .map_err(|_| reject(unavailable()))?;
        targets.insert(key);
        permit.send(job);
        Ok(())
    }
    async fn run_job(&self, state: &NativeState, mut job: Job, stop: watch::Receiver<bool>) {
        let _running = RunningJob {
            service: self,
            target: job.plan.request.target.key(),
            id: job.reservation.id.clone(),
        };
        let preparation = wire::bounded(job.deadline, stop.clone(), async {
            state.require_running()?;
            prepare(state, &self.policy, &mut job.plan).await?;
            state.require_running()?;
            if *stop.borrow() {
                return Err(paused());
            }
            Ok(())
        })
        .await;
        match preparation {
            Ok(Ok(())) => {
                let accepted = {
                    let gate = self.gate.lock();
                    if gate.state != WorkerState::Running || *stop.borrow() {
                        self.operations.reject(&job.reservation.id, paused());
                        false
                    } else if let Err(error) = state.require_running() {
                        self.operations.reject(&job.reservation.id, error);
                        false
                    } else {
                        self.operations.accept(&job.reservation.id)
                    }
                };
                if accepted {
                    self.operations.running(&job.reservation.id);
                    execute(state, &mut job.plan, job.deadline, stop).await;
                    self.operations
                        .succeed(&job.reservation.id, OperationResult::Probe(job.plan.result));
                }
            }
            Ok(Err(error)) => {
                self.operations.reject(&job.reservation.id, error);
            }
            Err(_) => {
                self.operations.reject(
                    &job.reservation.id,
                    if *stop.borrow() {
                        paused()
                    } else {
                        unavailable()
                    },
                );
            }
        }
    }
}

pub(super) async fn create(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let deadline = Instant::now() + DEADLINE;
    parse_query(request.uri(), &[], id)?;
    let mut keys = request.headers().get_all("idempotency-key").iter();
    let key = keys
        .next()
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| invalid())?;
    if keys.next().is_some() {
        return Err(invalid());
    }
    let json_type = request
        .headers()
        .get_all("content-type")
        .iter()
        .collect::<Vec<_>>();
    if json_type.len() != 1
        || !json_type[0]
            .to_str()
            .ok()
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Expected application/json.",
            None,
        ));
    }
    let service = &state.observation.probes;
    let guard = service.request();
    let body = axum::body::to_bytes(request.into_body(), 65536);
    let bytes = if let Some(cancel) = &guard.cancel {
        wire::bounded(deadline, cancel.clone(), body)
            .await
            .map_err(|_| {
                if *cancel.borrow() {
                    paused()
                } else {
                    unavailable()
                }
            })?
    } else {
        tokio::time::timeout_at(deadline, body)
            .await
            .map_err(|_| unavailable())?
    }
    .map_err(|_| too_large())?;
    let reservation = service.operations.reserve(
        if state.settings.secret.is_empty() {
            "anonymous"
        } else {
            "control"
        },
        "POST",
        "/api/v1/probes",
        key.as_deref(),
        &bytes,
        OperationKind::Probe,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        let operation_id = reservation.id.clone();
        let preparation = async {
            state.require_running()?;
            let Some(cancel) = &guard.cancel else {
                return Err(
                    if matches!(
                        service.gate.lock().state,
                        WorkerState::Paused | WorkerState::Transitioning
                    ) {
                        paused()
                    } else {
                        unavailable()
                    },
                );
            };
            if *cancel.borrow() {
                return Err(paused());
            }
            let request: ProbeRequest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            validate(&request)?;
            let plan = capture(state, request).await?;
            state.require_running()?;
            service.rate.admit(id)?;
            Ok(plan)
        };
        let result = if let Some(cancel) = &guard.cancel {
            wire::bounded(deadline, cancel.clone(), preparation)
                .await
                .unwrap_or_else(|_| {
                    Err(if *cancel.borrow() {
                        paused()
                    } else {
                        unavailable()
                    })
                })
        } else {
            preparation.await
        };
        match result {
            Ok(plan) => service.enqueue(Job {
                reservation,
                plan,
                deadline,
            })?,
            Err(error) => {
                service.operations.reject(&operation_id, error.clone());
                return Err(error);
            }
        }
    }
    drop(guard);
    Ok(admission.await?.into_response())
}
fn validate(request: &ProbeRequest) -> Result<(), ApiError> {
    if match &request.target {
        Target::Node { node_id } => node_id.is_empty(),
        Target::Group { group_id } => group_id.is_empty(),
    } {
        return Err(invalid());
    }
    if request.transport.is_empty()
        || request.transport.len() > 2
        || request.transport.len() == 2 && request.transport[0] == request.transport[1]
        || matches!(request.target, Target::Node { .. }) && request.members.is_some()
    {
        return Err(invalid());
    }
    if (request.kind == Kind::Dns) != (request.purpose == Purpose::Dns)
        || request.kind != Kind::Dns && request.transport != [Transport::Tcp]
    {
        return Err(invalid());
    }
    if let Some(Members::Ids(ids)) = &request.members {
        if ids.is_empty()
            || ids.iter().any(String::is_empty)
            || ids.iter().collect::<HashSet<_>>().len() != ids.len()
        {
            return Err(invalid());
        }
        if ids.len() > MAX_MEMBERS {
            return Err(too_large());
        }
    }
    Ok(())
}

async fn capture(state: &NativeState, request: ProbeRequest) -> Result<Plan, ApiError> {
    // Publication holds router before config; all later owner snapshots are synchronous.
    let _router = state.traffic_router.read().await;
    let config_guard = state.config.read().await;
    let config = Arc::clone(&config_guard);
    let manager = state.group_manager.read().clone();
    let registry = state.runtime_registry.read().clone();
    let identity = state.observation.catalog.snapshot();
    let dns = if let Some(provider) = state.dns.provider() {
        DnsPin::Runtime(
            provider
                .try_acquire()
                .map_err(|_| state.require_running().err().unwrap_or_else(unavailable))?,
        )
    } else {
        DnsPin::Standalone(state.dns.forwarder())
    };
    let group = match &request.target {
        Target::Node { .. } => None,
        Target::Group { group_id } => Some(
            identity
                .groups
                .iter()
                .find(|(_, id)| *id == group_id)
                .map(|(name, _)| name.clone())
                .ok_or_else(not_found)?,
        ),
    };
    if group
        .as_ref()
        .is_some_and(|name| !manager.native_probe_plan_within_limit(name, MAX_RESULTS))
    {
        return Err(too_large());
    }
    let members: Vec<_> = if let Some(group) = &group {
        match request.members.as_ref() {
            Some(Members::Scope(MemberScope::Leaves)) => manager
                .native_probe_leaves(group, MAX_MEMBERS + 1)
                .into_iter()
                .map(NativeGroupMember::Node)
                .collect(),
            _ => {
                let mut members = Vec::new();
                for member in manager.native_members(group) {
                    if let Some(Members::Ids(ids)) = &request.members {
                        let id = member_id(member, &identity).ok_or_else(not_found)?;
                        if !ids.contains(&id) {
                            continue;
                        }
                    }
                    members.push(member);
                    if members.len() > MAX_MEMBERS {
                        break;
                    }
                }
                if let Some(Members::Ids(ids)) = &request.members
                    && members.len() != ids.len()
                {
                    return Err(not_found());
                }
                members
            }
        }
    } else {
        let Target::Node { node_id } = &request.target else {
            unreachable!()
        };
        vec![NativeGroupMember::Node(
            config
                .nodes
                .iter()
                .find(|node| node.id.to_string() == *node_id)
                .ok_or_else(not_found)?,
        )]
    };
    let families: &[Family] = match request.ip_version {
        RequestedFamily::Ipv4 => &[Family::Ipv4],
        RequestedFamily::Ipv6 => &[Family::Ipv6],
        RequestedFamily::Any => &[Family::Ipv4, Family::Ipv6],
    };
    if members.len() > MAX_MEMBERS
        || members
            .len()
            .saturating_mul(families.len())
            .saturating_mul(request.transport.len())
            > MAX_RESULTS
    {
        return Err(too_large());
    }
    let before = selections(&manager, &identity, group.as_deref());
    let mut rows = Vec::new();
    let mut attempts: Vec<Attempt> = Vec::new();
    let mut unique: HashMap<(Uuid, Transport, Family), usize> = HashMap::new();
    for member in members {
        let member_id = member_id(member, &identity).ok_or_else(not_found)?;
        if let NativeGroupMember::Node(node) = member {
            if request.kind == Kind::TcpConnect
                && matches!(
                    node.protocol(),
                    honk_config::types::NodeProtocol::Direct
                        | honk_config::types::NodeProtocol::Block
                )
            {
                return Err(unsupported());
            }
            if request.transport.contains(&Transport::Udp)
                && !(honk_outbound::descriptor::descriptor(node.protocol()).supports_udp)(node)
            {
                return Err(unsupported());
            }
        }
        for &transport in &request.transport {
            for &family in families {
                let domain = if transport == Transport::Tcp {
                    ProbeDomain::Tcp
                } else {
                    ProbeDomain::DnsUdp
                };
                let leaf = manager.native_probe_leaf(member, domain, family.ip());
                let index = rows.len();
                rows.push(ResultRow {
                    member_id: member_id.clone(),
                    resolved_leaf_node_id: leaf.map(|node| node.id.to_string()),
                    kind: request.kind,
                    purpose: request.purpose,
                    transport,
                    ip_version: family,
                    warmth: "unknown",
                    state: if leaf.is_some() {
                        "unknown"
                    } else {
                        "unavailable"
                    },
                    latency_ms: None,
                    health_updated: false,
                    error: Some(if leaf.is_some() {
                        "not_started"
                    } else {
                        "no_eligible_leaf"
                    }),
                    observed_at: timestamp(SystemTime::now()),
                });
                if let Some(node) = leaf {
                    if request.kind == Kind::TcpConnect
                        && matches!(
                            node.protocol(),
                            honk_config::types::NodeProtocol::Direct
                                | honk_config::types::NodeProtocol::Block
                        )
                    {
                        return Err(unsupported());
                    }
                    if request.kind != Kind::TcpConnect {
                        let entry = state
                            .proxy_registry
                            .find(node.protocol())
                            .ok_or_else(unsupported)?;
                        if transport == Transport::Udp
                            && (!(entry.descriptor.supports_udp)(node) || entry.packet.is_none())
                        {
                            return Err(unsupported());
                        }
                    }
                    if let Some(&attempt) = unique.get(&(node.id, transport, family)) {
                        attempts[attempt].rows.push(index);
                    } else {
                        unique.insert((node.id, transport, family), attempts.len());
                        attempts.push(Attempt {
                            node: node.clone(),
                            ticket: state.alive_set.native_probe_ticket(node.id),
                            transport,
                            family,
                            rows: vec![index],
                            addr: None,
                            server: None,
                        });
                    }
                }
            }
        }
    }
    let (http, destination) = match request.kind {
        Kind::TcpConnect => (None, None),
        Kind::Http => {
            let url = group
                .as_ref()
                .and_then(|name| manager.native_group(name))
                .and_then(|group| group.check_url.as_deref())
                .or_else(|| config.global.tcp_check_url.first().map(String::as_str))
                .ok_or_else(unsupported)?;
            let http = honk_outbound::urltest::health_http_probe_request(
                url,
                &config.global.tcp_check_http_method,
            )
            .map_err(|_| unsupported())?;
            let host = http
                .uri()
                .host()
                .ok_or_else(unsupported)?
                .trim_matches(['[', ']'])
                .to_owned();
            let port =
                http.uri()
                    .port_u16()
                    .unwrap_or(if http.uri().scheme_str() == Some("https") {
                        443
                    } else {
                        80
                    });
            (Some(http), Some((host, port)))
        }
        Kind::Dns => {
            match honk_config::check::select_dns_check_target(&config.global.udp_check_dns)
                .map_err(|_| unsupported())?
                .ok_or_else(unsupported)?
            {
                honk_config::check::DnsCheckTarget::Literal(addr) => {
                    (None, Some((addr.ip().to_string(), addr.port())))
                }
                honk_config::check::DnsCheckTarget::Domain { host, port } => {
                    (None, Some((host.to_owned(), port)))
                }
            }
        }
    };
    let result = ProbeResult {
        target: request.target.clone(),
        selection_changed: TransportMap {
            tcp: false,
            udp: false,
        },
        selection_before: before.clone(),
        selection_after: before,
        results: rows,
    };
    drop(config_guard);
    Ok(Plan {
        request,
        config,
        manager,
        identity,
        registry,
        dns,
        group,
        http,
        destination,
        result,
        attempts,
    })
}

fn member_id(member: NativeGroupMember<'_>, identity: &CatalogIdentity) -> Option<String> {
    match member {
        NativeGroupMember::Node(node) => Some(node.id.to_string()),
        NativeGroupMember::Group(group) => identity.groups.get(&group.name).cloned(),
    }
}
fn selections(
    manager: &GroupManager,
    identity: &CatalogIdentity,
    group: Option<&str>,
) -> TransportMap<Option<String>> {
    let pick = |network| {
        group
            .and_then(|name| manager.native_selection(name, network))
            .and_then(|selection| member_id(selection.member, identity))
    };
    TransportMap {
        tcp: pick(SelectionNetwork::Tcp),
        udp: pick(SelectionNetwork::Udp),
    }
}

async fn prepare(state: &NativeState, policy: &Policy, plan: &mut Plan) -> Result<(), ApiError> {
    let https = plan
        .http
        .as_ref()
        .is_some_and(|request| request.uri().scheme_str() == Some("https"));
    let mut resolved: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for attempt in &mut plan.attempts {
        let (host, port) = plan
            .destination
            .as_ref()
            .map(|(host, port)| (host.as_str(), *port))
            .unwrap_or((attempt.node.host(), attempt.node.port));
        if !policy.port(plan.request.kind, port, https) {
            return Err(unsupported());
        }
        let ips = resolve(state, &plan.dns, &mut resolved, host).await;
        if ips.iter().any(|&ip| !policy.address(ip)) {
            return Err(unsupported());
        }
        attempt.addr = ips
            .iter()
            .copied()
            .find(|&ip| attempt.family.matches(ip))
            .map(|ip| SocketAddr::new(ip, port));
        if plan.request.kind != Kind::TcpConnect
            && attempt.node.protocol() != honk_config::types::NodeProtocol::Direct
        {
            let ips = resolve(state, &plan.dns, &mut resolved, attempt.node.host()).await;
            if ips.iter().any(|&ip| !policy.address(ip)) {
                return Err(unsupported());
            }
            attempt.server = ips.first().copied();
            if attempt.server.is_none() {
                attempt.addr = None;
            }
        }
        if attempt.transport == Transport::Udp
            && !honk_outbound::descriptor::udp_target_allowed(&attempt.node, port)
        {
            return Err(unsupported());
        }
        if attempt.addr.is_none() {
            for &row in &attempt.rows {
                plan.result.results[row].error = Some("address_unavailable");
                plan.result.results[row].observed_at = timestamp(SystemTime::now());
            }
        }
    }
    Ok(())
}

async fn resolve(
    state: &NativeState,
    dns: &DnsPin,
    resolved: &mut HashMap<String, Vec<IpAddr>>,
    host: &str,
) -> Vec<IpAddr> {
    if let Ok(ip) = host.trim_matches(['[', ']']).parse() {
        return vec![normalize(ip)];
    }
    if let Some(ips) = resolved.get(host) {
        return ips.clone();
    }
    let mut ips = Vec::new();
    for qtype in [1, 28] {
        let query = crate::dns::forwarder::build_dns_query(host, qtype);
        let outcome = match dns {
            DnsPin::Runtime(lease) => {
                let Ok(_permit) = lease.runtime().try_acquire_query() else {
                    continue;
                };
                state
                    .dns
                    .resolve_outcome_with_runtime(
                        lease,
                        &query,
                        crate::dns::query::DnsRequestMeta::EMPTY,
                        crate::dns::query::IngressProfile::Api,
                    )
                    .await
            }
            DnsPin::Standalone(forwarder) => forwarder
                .resolve_outcome_with_context_and_profile(
                    &query,
                    crate::dns::query::DnsRequestMeta::EMPTY,
                    crate::dns::query::IngressProfile::Api,
                )
                .await
                .map_err(Into::into),
        };
        if let Ok(outcome) = outcome {
            for ip in outcome.answer_ips().iter().copied().map(normalize) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    resolved.insert(host.to_owned(), ips.clone());
    ips
}

async fn execute(
    state: &NativeState,
    plan: &mut Plan,
    deadline: Instant,
    stop: watch::Receiver<bool>,
) {
    for attempt in &plan.attempts {
        let Some(addr) = attempt.addr else {
            continue;
        };
        if *stop.borrow() || Instant::now() >= deadline {
            for &row in &attempt.rows {
                plan.result.results[row].error = Some(if *stop.borrow() {
                    "cancelled"
                } else {
                    "deadline"
                });
                plan.result.results[row].observed_at = timestamp(SystemTime::now());
            }
            continue;
        }
        let outcome = wire::attempt(state, plan, attempt, addr, deadline, stop.clone()).await;
        let sample = outcome.sample;
        let completed = outcome.completed;
        let error = outcome.error;
        let warmth = if sample.is_some() {
            if plan.request.kind == Kind::Http && plan.request.warmth == Warmth::Warm {
                "warm"
            } else {
                "cold"
            }
        } else {
            "unknown"
        };
        let observed_at = outcome.observed_at;
        let observation = NativeHealthObservation {
            transport: if attempt.transport == Transport::Tcp {
                HealthTransport::Tcp
            } else {
                HealthTransport::Udp
            },
            purpose: if plan.request.purpose == Purpose::Data {
                HealthPurpose::Data
            } else {
                HealthPurpose::Dns
            },
            measurement: match plan.request.kind {
                Kind::TcpConnect => HealthMeasurement::TcpConnect,
                Kind::Http => HealthMeasurement::HttpHeaders,
                Kind::Dns => HealthMeasurement::DnsRoundTrip,
            },
            ip_version: attempt.family.ip(),
            warmth: match warmth {
                "cold" => HealthWarmth::Cold,
                "warm" => HealthWarmth::Warm,
                _ => HealthWarmth::Unknown,
            },
            sample_source: "probe",
            state: if sample.is_some() {
                HealthState::Healthy
            } else {
                HealthState::Unavailable
            },
            latency: sample.map(|sample| sample.latency),
            observed_at,
            error,
        };
        for &index in &attempt.rows {
            let row = &mut plan.result.results[index];
            let context = match &plan.request.target {
                Target::Group { group_id } => Some(NativeGroupProbeContext {
                    group_id: Uuid::parse_str(group_id).expect("catalog UUID"),
                    member_id: Uuid::parse_str(&row.member_id).expect("catalog member UUID"),
                }),
                Target::Node { .. } => None,
            };
            row.health_updated = completed
                && state
                    .alive_set
                    .complete_native_probe(&attempt.ticket, context, observation);
            row.state = if sample.is_some() {
                "healthy"
            } else if completed {
                "unavailable"
            } else {
                "unknown"
            };
            row.latency_ms = sample.map(|sample| sample.latency.as_secs_f64() * 1000.0);
            row.warmth = warmth;
            row.error = error;
            row.observed_at = timestamp(observed_at);
        }
    }
    plan.result.selection_after = selections(&plan.manager, &plan.identity, plan.group.as_deref());
    plan.result.selection_changed = TransportMap {
        tcp: plan.result.selection_before.tcp != plan.result.selection_after.tcp,
        udp: plan.result.selection_before.udp != plan.result.selection_after.udp,
    };
}
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}
fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid probe request.",
        None,
    )
}
fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedValue,
        "The configured probe target or protocol is not permitted.",
        None,
    )
}
fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Probe target or member was not found.",
        None,
    )
}
fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::RequestTooLarge,
        "Probe fan-out exceeds its bounded limits.",
        None,
    )
}
fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Probe admission is temporarily unavailable.",
        None,
    )
    .with_retry_after(1)
}
fn paused() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::StateConflict,
        "Probe admission is paused.",
        None,
    )
}
