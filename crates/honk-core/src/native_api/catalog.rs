//! Process-local identities and bounded, immutable native node pages.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque},
    io::{self, Write},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use axum::{
    Json,
    body::Body,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use honk_config::{
    Config,
    group::{Group, GroupPolicy},
};
use honk_outbound::{
    alive::{AliveDialerSet, IpVersion, NativeHealthObservation},
    group::{GroupManager, NativeGroupMember, SelectionNetwork},
};
use parking_lot::{Mutex, RwLock};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    ApiError, ErrorCode, NativeState, config::ListenerSecrets, error, invalid_query, parse_query,
    timestamp, types::RequestId,
};

const SNAPSHOT_TTL: Duration = Duration::from_secs(30);
const MAX_SNAPSHOTS: usize = 8;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PAGE_SIZE: usize = 1000;

pub(crate) struct CatalogIdentity {
    pub(crate) revision: String,
    pub(crate) groups: HashMap<String, String>,
}

pub(crate) struct Catalog {
    identity: RwLock<Arc<CatalogIdentity>>,
    snapshots: Mutex<VecDeque<NodeSnapshot>>,
}

impl Catalog {
    pub(crate) fn new(config: &Config) -> Self {
        let catalog = Self {
            identity: RwLock::new(Arc::new(CatalogIdentity {
                revision: String::new(),
                groups: HashMap::new(),
            })),
            snapshots: Mutex::new(VecDeque::new()),
        };
        catalog.install(config);
        catalog
    }

    pub(crate) fn install(&self, config: &Config) {
        let mut identity = self.identity.write();
        *identity = Self::prepare_identity(config, &identity);
    }

    pub(crate) fn prepare(&self, config: &Config) -> Arc<CatalogIdentity> {
        Self::prepare_identity(config, &self.identity.read())
    }

    /// The configuration publisher installs the same identity bound to its DNS runtime.
    pub(crate) fn install_prepared(&self, identity: Arc<CatalogIdentity>) {
        *self.identity.write() = identity;
    }

    fn prepare_identity(config: &Config, identity: &Arc<CatalogIdentity>) -> Arc<CatalogIdentity> {
        let effective = GroupManager::native_effective_groups(&config.groups);
        let revision = config_revision(config, &effective);
        if identity.revision == revision {
            return Arc::clone(identity);
        }
        let groups = effective
            .keys()
            .map(|name| {
                let id = identity
                    .groups
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                (name.clone(), id)
            })
            .collect();
        Arc::new(CatalogIdentity { revision, groups })
    }

    pub(crate) fn snapshot(&self) -> Arc<CatalogIdentity> {
        self.identity.read().clone()
    }

    fn page(
        &self,
        snapshot: NodeSnapshot,
        limit: usize,
        id: &RequestId,
    ) -> Result<Response, ApiError> {
        let response = snapshot.page(0, limit);
        if snapshot.nodes.len() > limit {
            let mut snapshots = self.snapshots.lock();
            snapshots.retain(|snapshot| snapshot.created.elapsed() < SNAPSHOT_TTL);
            while snapshots.len() >= MAX_SNAPSHOTS
                || snapshots
                    .iter()
                    .map(|snapshot| snapshot.bytes)
                    .sum::<usize>()
                    + snapshot.bytes
                    > MAX_SNAPSHOT_BYTES
            {
                if snapshots.pop_front().is_none() {
                    return Err(snapshot_unavailable(id));
                }
            }
            snapshots.push_back(snapshot);
        }
        Ok(response)
    }

    fn resume(
        &self,
        cursor: &str,
        group_id: Option<&str>,
        limit: usize,
        id: &RequestId,
    ) -> Result<Response, ApiError> {
        let (snapshot_id, offset) = cursor.split_once(':').ok_or_else(|| invalid_query(id))?;
        let snapshot_id = Uuid::parse_str(snapshot_id).map_err(|_| invalid_query(id))?;
        let offset: usize = offset.parse().map_err(|_| invalid_query(id))?;
        let mut snapshots = self.snapshots.lock();
        snapshots.retain(|snapshot| snapshot.created.elapsed() < SNAPSHOT_TTL);
        let snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot.id == snapshot_id)
            .ok_or_else(|| invalid_query(id))?;
        if snapshot.group_id.as_deref() != group_id || offset == 0 || offset >= snapshot.nodes.len()
        {
            return Err(invalid_query(id));
        }
        Ok(snapshot.page(offset, limit))
    }
}

fn policy(policy: GroupPolicy) -> &'static str {
    match policy {
        GroupPolicy::Selector => "selector",
        GroupPolicy::URLTest => "urltest",
        GroupPolicy::LoadBalance => "loadbalance",
        GroupPolicy::Fallback => "fallback",
        GroupPolicy::Score => "score",
    }
}

pub(super) fn check_url(group: &Group) -> Option<String> {
    normalized_check_url(group.check_url.as_deref()?)
}

/// The URL a health check probes, as GET reports and PATCH writes it.
pub(super) fn normalized_check_url(value: &str) -> Option<String> {
    let target = honk_config::check::decode_http_check_target(value, false).ok()?;
    Some(format!(
        "{}://{}{}",
        if target.is_https() { "https" } else { "http" },
        target.authority(),
        target.request_target()
    ))
}

/// Only URLTest switches on latency; other policies have no tolerance to report.
pub(super) fn tolerance(group: &Group) -> Option<u64> {
    (group.policy == honk_config::group::GroupPolicy::URLTest).then_some(group.tolerance)
}

pub(crate) fn revision_for(config: &Config) -> String {
    config_revision(
        config,
        &GroupManager::native_effective_groups(&config.groups),
    )
}

fn config_revision(config: &Config, groups: &HashMap<String, Group>) -> String {
    let nodes: HashMap<_, _> = config.nodes.iter().map(|node| (node.id, node)).collect();
    let mut ordered: Vec<_> = groups.values().collect();
    ordered.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    let canonical: Vec<_> = ordered
        .into_iter()
        .map(|group| {
            let nodes: Vec<_> = group
                .nodes
                .iter()
                .filter_map(|id| nodes.get(id))
                .map(|node| (node.id, &node.name))
                .collect();
            let children: Vec<_> = group
                .groups
                .iter()
                .filter(|name| groups.contains_key(*name))
                .collect();
            let mut filters: Vec<_> = group.filters.iter().collect();
            filters.sort_unstable();
            filters.dedup();
            json!([
                group.name,
                group.icon,
                policy(group.policy),
                nodes,
                children,
                filters,
                group.default,
                group.final_outbound,
                check_url(group),
                group.check_interval,
                tolerance(group),
                group.idle_timeout,
                group.interrupt_connections
            ])
        })
        .collect();
    let digest = Sha256::digest(serde_json::to_vec(&canonical).expect("catalog values serialize"));
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct NodeSnapshot {
    id: Uuid,
    group_id: Option<String>,
    observed_at: String,
    created: Instant,
    nodes: Vec<Box<str>>,
    bytes: usize,
}

impl NodeSnapshot {
    fn page(&self, offset: usize, limit: usize) -> Response {
        let end = offset.saturating_add(limit).min(self.nodes.len());
        let cursor = (end < self.nodes.len()).then(|| format!("{}:{end}", self.id));
        let mut body = format!("{{\"observed_at\":\"{}\",\"nodes\":[", self.observed_at);
        for (index, node) in self.nodes[offset..end].iter().enumerate() {
            if index != 0 {
                body.push(',');
            }
            body.push_str(node);
        }
        body.push_str("],\"next_cursor\":");
        body.push_str(&serde_json::to_string(&cursor).expect("cursor serializes"));
        body.push('}');
        (
            [(header::CONTENT_TYPE, "application/json")],
            Body::from(body),
        )
            .into_response()
    }
}

struct BoundedJson {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("snapshot capacity"));
        }
        let required = self.bytes.len() + bytes.len();
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.limit);
            self.bytes.reserve_exact(capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn health(observation: NativeHealthObservation) -> Value {
    json!({
        "transport": observation.transport,
        "purpose": observation.purpose,
        "ip_version": match observation.ip_version { IpVersion::V4 => "ipv4", IpVersion::V6 => "ipv6" },
        "warmth": observation.warmth,
        "measurement": observation.measurement,
        "sample_source": observation.sample_source,
        "state": observation.state,
        "latency_ms": observation.latency.map(|latency| latency.as_secs_f64() * 1000.0),
        "moving_avg_ms": null,
        "avg10_ms": null,
        "observed_at": timestamp(observation.observed_at),
        "error": observation.error,
    })
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum ProviderId {
    Subscription(Uuid),
    Inline(&'static str),
}

#[derive(serde::Serialize)]
struct NodeRow<'a> {
    id: Uuid,
    name: Cow<'a, str>,
    protocol: &'static str,
    subscription_tag: Option<Cow<'a, str>>,
    provider_id: Option<ProviderId>,
    group_ids: Vec<&'a String>,
    health: Vec<Value>,
}

pub(super) fn is_inline_node(node: &honk_config::node::Node) -> bool {
    node.subscription_id.is_none()
        && !matches!(
            node.protocol(),
            honk_config::types::NodeProtocol::Direct | honk_config::types::NodeProtocol::Block
        )
}

fn node_row<'a>(
    node: &'a honk_config::node::Node,
    config: &'a Config,
    alive: &AliveDialerSet,
    group_ids: Vec<&'a String>,
    secrets: &ListenerSecrets,
) -> NodeRow<'a> {
    NodeRow {
        id: node.id,
        name: secrets.mask_borrowed(&node.name),
        protocol: node.protocol().as_str(),
        subscription_tag: node
            .subscription_id
            .and_then(|id| {
                config
                    .subscriptions
                    .iter()
                    .find(|subscription| subscription.id == id)
            })
            .map(|subscription| secrets.mask_borrowed(&subscription.name)),
        provider_id: node
            .subscription_id
            .map(ProviderId::Subscription)
            .or_else(|| is_inline_node(node).then_some(ProviderId::Inline("inline"))),
        group_ids,
        health: alive
            .native_observations(node.id)
            .into_iter()
            .map(health)
            .collect(),
    }
}

pub(super) fn node_value(
    config: &Config,
    identity: &CatalogIdentity,
    manager: &GroupManager,
    alive: &AliveDialerSet,
    node_id: Uuid,
    secrets: &ListenerSecrets,
) -> Option<Value> {
    let node = config.nodes.iter().find(|node| node.id == node_id)?;
    let mut groups: Vec<_> = identity
        .groups
        .iter()
        .filter_map(|(name, id)| {
            manager
                .native_members(name)
                .any(|member| matches!(member, NativeGroupMember::Node(node) if node.id == node_id))
                .then_some(id)
        })
        .collect();
    groups.sort_unstable();
    groups.dedup();
    serde_json::to_value(node_row(node, config, alive, groups, secrets)).ok()
}

fn node_snapshot(
    config: &Config,
    manager: &GroupManager,
    identity: &CatalogIdentity,
    alive: &AliveDialerSet,
    group_id: Option<&str>,
    id: &RequestId,
    secrets: &ListenerSecrets,
) -> Result<NodeSnapshot, ApiError> {
    let filter = match group_id {
        Some(group_id) => Some(
            identity
                .groups
                .iter()
                .find(|(_, value)| value.as_str() == group_id)
                .map(|(name, _)| name.as_str())
                .ok_or_else(|| group_not_found(id))?,
        ),
        None => None,
    };
    let filter_nodes: Option<HashSet<_>> = filter.map(|name| {
        manager
            .native_members(name)
            .filter_map(|member| match member {
                NativeGroupMember::Node(node) => Some(node.id),
                NativeGroupMember::Group(_) => None,
            })
            .collect()
    });
    let mut nodes: Vec<_> = config
        .nodes
        .iter()
        .filter(|node| {
            filter_nodes
                .as_ref()
                .is_none_or(|filter| filter.contains(&node.id))
        })
        .collect();
    nodes.sort_unstable_by_key(|node| node.id);
    let mut snapshot = NodeSnapshot {
        id: Uuid::new_v4(),
        group_id: group_id.map(str::to_owned),
        observed_at: timestamp(SystemTime::now()),
        created: Instant::now(),
        nodes: Vec::new(),
        bytes: 0,
    };
    let overhead = std::mem::size_of::<NodeSnapshot>()
        + snapshot.group_id.as_ref().map_or(0, String::len)
        + snapshot.observed_at.len()
        + nodes.len().saturating_mul(std::mem::size_of::<Box<str>>());
    if overhead > MAX_SNAPSHOT_BYTES {
        return Err(snapshot_unavailable(id));
    }
    snapshot.nodes = Vec::with_capacity(nodes.len());
    snapshot.bytes = overhead;
    let mut membership: HashMap<Uuid, Vec<&String>> = HashMap::new();
    for (name, group_id) in &identity.groups {
        for member in manager.native_members(name) {
            if let NativeGroupMember::Node(node) = member {
                membership.entry(node.id).or_default().push(group_id);
            }
        }
    }
    for node in nodes {
        let mut group_ids = membership.remove(&node.id).unwrap_or_default();
        group_ids.sort_unstable();
        group_ids.dedup();
        let value = node_row(node, config, alive, group_ids, secrets);
        let mut writer = BoundedJson {
            bytes: Vec::new(),
            limit: MAX_SNAPSHOT_BYTES - snapshot.bytes,
        };
        serde_json::to_writer(&mut writer, &value).map_err(|_| snapshot_unavailable(id))?;
        snapshot.bytes += writer.bytes.len();
        snapshot.nodes.push(
            String::from_utf8(writer.bytes)
                .expect("JSON is UTF-8")
                .into_boxed_str(),
        );
    }
    Ok(snapshot)
}

pub(super) async fn nodes(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let query = parse_query(uri, &["group_id", "limit", "cursor"], id)?;
    let limit = query
        .get("limit")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| invalid_query(id))?
        .unwrap_or(100);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) || query.get("group_id").is_some_and(String::is_empty)
    {
        return Err(invalid_query(id));
    }
    let group_id = query.get("group_id").map(String::as_str);
    if let Some(cursor) = query.get("cursor") {
        return state
            .observation
            .catalog
            .resume(cursor, group_id, limit, id);
    }
    let config = state.config.read().await;
    let identity = state.observation.catalog.snapshot();
    let manager = state.group_manager.read().clone();
    let secrets = listener_secrets(state);
    let snapshot = node_snapshot(
        &config,
        &manager,
        &identity,
        &state.alive_set,
        group_id,
        id,
        &secrets,
    )?;
    drop(config);
    state.observation.catalog.page(snapshot, limit, id)
}

pub(super) async fn node(
    state: &NativeState,
    node_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let config = state.config.read().await;
    let identity = state.observation.catalog.snapshot();
    let manager = state.group_manager.read().clone();
    Uuid::parse_str(node_id)
        .ok()
        .and_then(|node_id| {
            node_value(
                &config,
                &identity,
                &manager,
                &state.alive_set,
                node_id,
                &listener_secrets(state),
            )
        })
        .map(|value| Json(value).into_response())
        .ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                ErrorCode::ResourceNotFound,
                "Node not found",
                id,
            )
        })
}

fn listener_secrets(state: &NativeState) -> ListenerSecrets {
    let accepted = state.observation.configuration.sources.accepted.read();
    state
        .observation
        .configuration
        .secrets(accepted.as_ref())
        .as_ref()
        .clone()
        .with_clash(&state.clash_secret)
}

fn member_id(member: NativeGroupMember<'_>, identity: &CatalogIdentity) -> Option<String> {
    match member {
        NativeGroupMember::Node(node) => Some(node.id.to_string()),
        NativeGroupMember::Group(group) => identity.groups.get(&group.name).cloned(),
    }
}

/// A group's current `{tcp, udp}` selections, `null` where none is formed.
pub(crate) fn runtime_selection(
    manager: &GroupManager,
    identity: &CatalogIdentity,
    group_name: &str,
) -> Value {
    let group = manager.native_group(group_name);
    let [tcp, udp] = [SelectionNetwork::Tcp, SelectionNetwork::Udp].map(|network| {
        group.map_or(Value::Null, |group| {
            selection(manager, group, network, identity)
        })
    });
    json!({ "tcp": tcp, "udp": udp })
}

fn selection(
    manager: &GroupManager,
    group: &Group,
    network: SelectionNetwork,
    identity: &CatalogIdentity,
) -> Value {
    let Some(selection) = manager.native_selection(&group.name, network) else {
        return Value::Null;
    };
    let Some(member_id) = member_id(selection.member, identity) else {
        return Value::Null;
    };
    json!({
        "member_id": member_id,
        "resolved_leaf_node_id": selection.leaf.map(|node| node.id.to_string()),
        "source": match group.policy {
            _ if manager.has_override(&group.name, network) => "override",
            GroupPolicy::Selector => "runtime",
            GroupPolicy::URLTest => "health",
            _ => "policy",
        }
    })
}

fn group_health(
    manager: &GroupManager,
    group: &Group,
    identity: &CatalogIdentity,
    alive: &AliveDialerSet,
) -> Vec<Value> {
    let group_id =
        Uuid::parse_str(&identity.groups[&group.name]).expect("catalog group IDs are UUIDs");
    // Accepted-epoch retention owns member/leaf associations, including explicit leaf probes.
    let samples = alive.native_group_observations(group_id);
    let mut result: Vec<_> = samples
        .iter()
        .map(|sample| {
            group_observation(
                sample.member_id.to_string(),
                sample.node_id,
                sample.observation,
            )
        })
        .collect();
    if group.check_url.is_none() {
        let mut seen = HashSet::new();
        for member in manager.native_members(&group.name) {
            let NativeGroupMember::Node(node) = member else {
                continue;
            };
            if !seen.insert(node.id) {
                continue;
            }
            for sample in alive.native_observations(node.id) {
                if samples.iter().any(|retained| {
                    retained.member_id == node.id
                        && retained.observation.transport == sample.transport
                        && retained.observation.purpose == sample.purpose
                        && retained.observation.measurement == sample.measurement
                        && retained.observation.ip_version == sample.ip_version
                        && retained.observation.warmth == sample.warmth
                }) {
                    continue;
                }
                result.push(group_observation(node.id.to_string(), node.id, sample));
            }
        }
    }
    result
}

fn group_observation(member_id: String, node_id: Uuid, sample: NativeHealthObservation) -> Value {
    let mut result = health(sample);
    result["member_id"] = json!(member_id);
    result["resolved_leaf_node_id"] = json!(node_id.to_string());
    result["sorting_latency_ms"] = Value::Null;
    result["ranking"] = Value::Null;
    result
}

fn group_value(
    manager: &GroupManager,
    group: &Group,
    identity: &CatalogIdentity,
    alive: &AliveDialerSet,
    full: bool,
) -> Value {
    let tcp = selection(manager, group, SelectionNetwork::Tcp, identity);
    let udp = selection(manager, group, SelectionNetwork::Udp, identity);
    let mut result = json!({
        "id": identity.groups[&group.name], "name": group.name, "icon": group.icon,
        "config_revision": identity.revision,
        "policy": { "kind": policy(group.policy), "native": policy(group.policy) }
    });
    if !full {
        result["member_count"] = json!(manager.native_members(&group.name).count());
        result["selection"] =
            json!({ "tcp_member_id": tcp["member_id"], "udp_member_id": udp["member_id"] });
        return result;
    }
    let members: Vec<_> = manager
        .native_members(&group.name)
        .filter_map(|member| {
            let id = member_id(member, identity)?;
            let (name, kind) = match member {
                NativeGroupMember::Node(node) => (&node.name, "node"),
                NativeGroupMember::Group(group) => (&group.name, "group"),
            };
            Some(json!({ "id": id, "name": name, "kind": kind }))
        })
        .collect();
    let default_id = group
        .default
        .as_ref()
        .and_then(|name| {
            members
                .iter()
                .find(|member| member["name"].as_str() == Some(name.as_str()))
        })
        .map(|member| member["id"].clone());
    result["members"] = json!(members);
    result["config"] = json!({
        "default_member_id": default_id, "final_outbound": group.final_outbound,
        "check_url": check_url(group), "check_interval": group.check_interval.filter(|value| *value > 0),
        "tolerance": tolerance(group), "idle_timeout": group.idle_timeout,
        "interrupt_connections": group.interrupt_connections
    });
    result["runtime"] = json!({ "selection": { "tcp": tcp, "udp": udp }, "health": group_health(manager, group, identity, alive) });
    result["capabilities"] = json!({
        "can_select": group.policy == honk_config::group::GroupPolicy::Selector, "can_override": group.policy != honk_config::group::GroupPolicy::Selector, "supports_nested_groups": true,
        "mutable_config": [], "probe_transports": ["tcp", "udp"]
    });
    result
}

pub(super) async fn groups(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let _config = state.config.read().await;
    let identity = state.observation.catalog.snapshot();
    let manager = state.group_manager.read().clone();
    let mut names: Vec<_> = identity.groups.keys().collect();
    names.sort_unstable();
    let revision = state
        .observation
        .configuration
        .sources
        .revision()
        .unwrap_or_else(|| identity.revision.clone());
    let groups: Vec<_> = names
        .into_iter()
        .filter_map(|name| manager.native_group(name))
        .map(|group| {
            let mut value = group_value(&manager, group, &identity, &state.alive_set, false);
            value["config_revision"] = json!(revision);
            value
        })
        .collect();
    Ok(Json(super::config::administrative_projection(
        state,
        Value::Array(groups),
    )?)
    .into_response())
}

pub(super) async fn group(
    state: &NativeState,
    group_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let _config = state.config.read().await;
    let identity = state.observation.catalog.snapshot();
    let manager = state.group_manager.read().clone();
    let name = identity
        .groups
        .iter()
        .find(|(_, id)| id.as_str() == group_id)
        .map(|(name, _)| name)
        .ok_or_else(|| group_not_found(id))?;
    let group = manager
        .native_group(name)
        .ok_or_else(|| group_not_found(id))?;
    let revision = state
        .observation
        .configuration
        .sources
        .revision()
        .unwrap_or_else(|| identity.revision.clone());
    let mut value = group_value(&manager, group, &identity, &state.alive_set, true);
    value["config_revision"] = json!(revision);
    if state.observation.configuration.group_writable(name) {
        let mutable: Vec<_> = super::groups::MUTABLE_CONFIG
            .into_iter()
            .filter(|field| *field != "tolerance" || tolerance(group).is_some())
            .collect();
        value["capabilities"]["mutable_config"] = json!(mutable);
    }
    let value = super::config::administrative_projection(state, value)?;
    Ok(([(header::ETAG, format!("\"{revision}\""))], Json(value)).into_response())
}

fn group_not_found(id: &RequestId) -> ApiError {
    error(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Group not found",
        id,
    )
}

pub(super) fn snapshot_unavailable(id: &RequestId) -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::SnapshotUnavailable,
        "A coherent snapshot is unavailable",
        id,
    )
}

#[cfg(test)]
mod tests;
