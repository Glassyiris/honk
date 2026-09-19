//! Process-local userspace evidence. Reads never consult routing or current groups.

use std::{
    collections::VecDeque,
    mem::size_of,
    net::SocketAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use axum::{
    Json,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    NativeState, error,
    events::EventHub,
    full_detail, invalid_query, parse_query, timestamp,
    types::{ApiError, ErrorCode, RequestId},
};

const MAX_RECORDS: usize = 1024;
const MAX_STEPS: usize = 64;
const MAX_BYTES: usize = 8 * 1024 * 1024;
/// Listings keep this much of the budget for their snapshots, so a ring that
/// has grown to its own limit still leaves room to page through it.
const SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;
const MAX_SNAPSHOTS: usize = 8;
const TERMINAL_TTL: Duration = Duration::from_secs(300);
const SNAPSHOT_TTL: Duration = Duration::from_secs(30);
/// Records leave the ring one at a time as flows end or newer ones need the
/// room, so a `flow.gap` per departure would shadow every flow under load.
/// Room-making is reported at most once per interval, with the cumulative
/// `dropped_records`; the count itself never skips.
const EVICTED_GAP_INTERVAL: Duration = Duration::from_secs(10);
const MAX_SAFE_UINT: u64 = 9_007_199_254_740_991;
const MAX_TEXT: usize = 512;
const MAX_STEP_BYTES: usize = 64 * 1024;
// Covers the bounded deque allocations, tombstones, filters, and owner metadata.
const OWNER_BYTES: usize = 256 * 1024;

pub(crate) struct FlowStore {
    instance_id: String,
    events: Arc<EventHub>,
    inner: Mutex<Store>,
}

struct Store {
    recording: bool,
    max_records: usize,
    retention: Duration,
    records: VecDeque<Record>,
    snapshots: Vec<Snapshot>,
    tombstones: VecDeque<(String, Instant)>,
    record_bytes: usize,
    snapshot_bytes: usize,
    dropped: u64,
    evicted_gap_at: Option<Instant>,
}

struct Record {
    summary: Value,
    input: Value,
    steps: Vec<Value>,
    started: Instant,
    ended: Option<Instant>,
    redacted: bool,
    overflow: bool,
    bytes: usize,
}

#[derive(Clone, PartialEq, Eq)]
struct Filters {
    network: String,
    state: String,
    connection_id: Option<String>,
    full: bool,
    limit: usize,
}

struct Snapshot {
    token: String,
    filters: Filters,
    rows: Vec<Value>,
    observed_at: String,
    dropped: String,
    created: Instant,
    bytes: usize,
}

pub(crate) struct FlowGuard {
    store: Weak<FlowStore>,
    id: String,
    replied: AtomicBool,
}

pub(crate) struct ConnectionEvidence {
    pub(crate) chain: Vec<String>,
    pub(crate) chain_source: &'static str,
    pub(crate) rule_id: Option<String>,
    pub(crate) rule_expression: Option<String>,
    pub(crate) rule_source: &'static str,
    pub(crate) domain_source: Option<&'static str>,
    pub(crate) started_at: String,
}

impl Store {
    fn new(recording: bool) -> Self {
        Self {
            recording,
            max_records: MAX_RECORDS,
            retention: TERMINAL_TTL,
            records: VecDeque::new(),
            snapshots: Vec::new(),
            tombstones: VecDeque::new(),
            record_bytes: 0,
            snapshot_bytes: 0,
            dropped: 0,
            evicted_gap_at: None,
        }
    }

    /// Everything the owner holds; the records' own share is bounded in
    /// `enforce_limit`, the listings' in `page`.
    #[cfg(test)]
    fn bytes(&self) -> usize {
        OWNER_BYTES + self.record_bytes + self.snapshot_bytes
    }
}

impl FlowStore {
    pub(crate) fn new(instance_id: String, events: Arc<EventHub>) -> Self {
        Self {
            instance_id,
            events,
            inner: Mutex::new(Store::new(true)),
        }
    }

    pub(crate) fn set_recording(&self, enabled: bool) {
        let mut store = self.inner.lock();
        if store.recording == enabled {
            return;
        }
        *store = Store::new(enabled);
        self.gap(&store, None, "recording_changed");
    }

    pub(crate) fn set_limits(&self, max_records: usize, retention_seconds: u64) {
        let mut store = self.inner.lock();
        if max_records < store.max_records
            || Duration::from_secs(retention_seconds) < store.retention
        {
            store.snapshots.clear();
            store.snapshot_bytes = 0;
        }
        store.max_records = max_records;
        store.retention = Duration::from_secs(retention_seconds);
        let now = Instant::now();
        self.prune(&mut store, now);
        self.enforce_limit(&mut store, now);
        store.records.shrink_to_fit();
        store.snapshots.shrink_to_fit();
    }

    pub(crate) fn maintain(&self) {
        self.prune(&mut self.inner.lock(), Instant::now());
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        network: &'static str,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> FlowGuard {
        let mut store = self.inner.lock();
        if !store.recording || !matches!(network, "tcp" | "udp") {
            return FlowGuard {
                store: Weak::new(),
                id: String::new(),
                replied: AtomicBool::new(false),
            };
        }
        let now = Instant::now();
        self.prune(&mut store, now);
        let id = Uuid::new_v4().to_string();
        let input = json!({
            "src": src.to_string(), "dst": dst.to_string(), "domain": null,
            "domain_source": null, "pid": null, "process_path": null, "src_mac": null,
            "ingress": null, "domain_rule_ids": null, "dscp": null, "mark": null
        });
        let mut record = Record {
            summary: json!({
                "id": id, "instance_id": self.instance_id, "revision": 1, "network": network,
                "state": "observed", "pname": null, "connection_id": null, "outbound": null,
                "chain": [], "chain_source": "unknown", "rule_id": null, "rule_expression": null,
                "rule_source": "unknown", "ingress": null, "domain_source": null,
                "observed_by": "userspace", "started_at": timestamp(SystemTime::now()),
                "ended_at": null, "trace_status": "partial"
            }),
            input,
            steps: Vec::new(),
            started: now,
            ended: None,
            redacted: false,
            overflow: false,
            bytes: 0,
        };
        let mut values = record.input.clone();
        values["pname"] = Value::Null;
        record.push_step("input", None, json!({"values": values, "source": "socket"}));
        record.bytes = record.retained_bytes();
        store.record_bytes += record.bytes;
        self.updated(&record);
        store.records.push_back(record);
        self.enforce_limit(&mut store, now);
        FlowGuard {
            store: Arc::downgrade(self),
            id,
            replied: AtomicBool::new(false),
        }
    }

    pub(crate) fn connection_evidence(&self, flow_id: &str) -> Option<ConnectionEvidence> {
        let mut store = self.inner.lock();
        self.prune(&mut store, Instant::now());
        let record = store.records.iter().find(|record| record.id() == flow_id)?;
        let summary = &record.summary;
        Some(ConnectionEvidence {
            chain: summary["chain"]
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            chain_source: if summary["chain_source"] == "evaluation" {
                "evaluation"
            } else {
                "unknown"
            },
            rule_id: summary["rule_id"].as_str().map(str::to_owned),
            rule_expression: summary["rule_expression"].as_str().map(str::to_owned),
            rule_source: rule_source(summary["rule_source"].as_str().unwrap_or("unknown")),
            domain_source: summary["domain_source"].as_str().map(domain_source),
            started_at: summary["started_at"].as_str()?.to_owned(),
        })
    }

    fn mutate(&self, id: &str, change: impl FnOnce(&mut Record) -> bool) {
        let mut store = self.inner.lock();
        let now = Instant::now();
        self.prune(&mut store, now);
        // ponytail: bounded 1024-record scan; add an ID index only if this becomes a measured bottleneck.
        let Some(index) = store.records.iter().position(|record| record.id() == id) else {
            return;
        };
        let record = &mut store.records[index];
        if record.ended.is_some() {
            return;
        }
        let old_bytes = record.bytes;
        let overflow = record.overflow;
        if !change(record) {
            return;
        }
        let revision = record.summary["revision"].as_u64().unwrap_or(1);
        if revision == MAX_SAFE_UINT {
            self.evict(&mut store, index, now, "buffer_overflow", false);
            return;
        }
        record.summary["revision"] = (revision + 1).into();
        record.bytes = record.retained_bytes();
        let new_bytes = record.bytes;
        let lost_steps = record.overflow && !overflow;
        self.updated(record);
        store.record_bytes = store.record_bytes - old_bytes + new_bytes;
        if lost_steps {
            self.gap(&store, Some(id), "buffer_overflow");
        }
        self.enforce_limit(&mut store, now);
    }

    fn updated(&self, record: &Record) {
        self.events.publish(
            "flow.updated",
            json!({
                "resource_id": record.id(), "revision": record.summary["revision"],
                "href": format!("/api/v1/flows/{}", record.id())
            }),
            Some(record.id()),
        );
    }

    fn gap(&self, store: &Store, id: Option<&str>, reason: &'static str) {
        self.events.publish(
            "flow.gap",
            json!({
                "resource_id": id, "reason": reason, "dropped_records": store.dropped.to_string()
            }),
            id,
        );
    }

    /// A record that lost its own history (`routine` false) is named in its
    /// gap; one that merely left the ring to make room is folded into the
    /// interval notice.
    fn evict(
        &self,
        store: &mut Store,
        index: usize,
        now: Instant,
        reason: &'static str,
        routine: bool,
    ) {
        let record = store.records.remove(index).expect("known record index");
        store.record_bytes -= record.bytes;
        store.dropped = store.dropped.saturating_add(1);
        if !routine {
            self.gap(store, Some(record.id()), reason);
        } else if store
            .evicted_gap_at
            .is_none_or(|at| now.saturating_duration_since(at) >= EVICTED_GAP_INTERVAL)
        {
            store.evicted_gap_at = Some(now);
            self.gap(store, None, reason);
        }
        if store.tombstones.len() == MAX_RECORDS {
            store.tombstones.pop_front();
        }
        store.tombstones.push_back((record.id().to_owned(), now));
    }

    fn enforce_limit(&self, store: &mut Store, now: Instant) {
        while store.records.len() > store.max_records
            || OWNER_BYTES + store.record_bytes > MAX_BYTES - SNAPSHOT_BYTES
        {
            if store.records.is_empty() {
                break;
            }
            self.evict(store, 0, now, "buffer_overflow", true);
        }
    }

    fn prune(&self, store: &mut Store, now: Instant) {
        store
            .snapshots
            .retain(|snapshot| now.saturating_duration_since(snapshot.created) < SNAPSHOT_TTL);
        store.snapshot_bytes = store.snapshots.iter().map(|snapshot| snapshot.bytes).sum();
        while store
            .tombstones
            .front()
            .is_some_and(|(_, at)| now.saturating_duration_since(*at) >= TERMINAL_TTL)
        {
            store.tombstones.pop_front();
        }
        let mut index = 0;
        while index < store.records.len() {
            if store.records[index]
                .ended
                .is_some_and(|ended| now.saturating_duration_since(ended) >= store.retention)
            {
                self.evict(store, index, now, "evicted", true);
            } else {
                index += 1;
            }
        }
    }

    fn page(
        &self,
        filters: Filters,
        cursor: Option<&str>,
        id: &RequestId,
    ) -> Result<Value, ApiError> {
        let mut store = self.inner.lock();
        self.prune(&mut store, Instant::now());
        if let Some(cursor) = cursor {
            let (token, offset) = cursor
                .rsplit_once('.')
                .ok_or_else(|| snapshot_expired(id))?;
            let offset = offset.parse::<usize>().map_err(|_| snapshot_expired(id))?;
            let snapshot = store
                .snapshots
                .iter()
                .find(|snapshot| snapshot.token == token)
                .filter(|snapshot| snapshot.filters == filters)
                .ok_or_else(|| snapshot_expired(id))?;
            if offset == 0 || offset >= snapshot.rows.len() || offset % filters.limit != 0 {
                return Err(snapshot_expired(id));
            }
            return Ok(self.snapshot_page(snapshot, offset, store.recording));
        }
        let count = store
            .records
            .iter()
            .filter(|record| filters.matches(record))
            .count();
        // Only a walk that continues past this page keeps a snapshot; a result
        // that fits in one page is answered from the records and costs no budget.
        let retained = count > filters.limit;
        let mut snapshot = Snapshot {
            token: Uuid::new_v4().to_string(),
            filters,
            rows: Vec::with_capacity(count),
            observed_at: timestamp(SystemTime::now()),
            dropped: store.dropped.to_string(),
            created: Instant::now(),
            bytes: size_of::<Snapshot>() + count * size_of::<Value>() + 8192,
        };
        for record in store
            .records
            .iter()
            .rev()
            .filter(|record| snapshot.filters.matches(record))
        {
            let row = record.project(snapshot.filters.full, false);
            snapshot.bytes += value_heap_bytes(&row);
            if retained && snapshot.bytes > SNAPSHOT_BYTES {
                return Err(snapshot_busy(id));
            }
            snapshot.rows.push(row);
        }
        if retained {
            // Older snapshots make room before a new walk is refused: a reader
            // still on one of those cursors gets `snapshot_expired` and starts
            // over, which the ttl would have given it thirty seconds later.
            while !store.snapshots.is_empty()
                && (store.snapshots.len() == MAX_SNAPSHOTS
                    || store.snapshot_bytes + snapshot.bytes > SNAPSHOT_BYTES)
            {
                let oldest = store
                    .snapshots
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, snapshot)| snapshot.created)
                    .map(|(index, _)| index)
                    .expect("a non-empty snapshot table has an oldest entry");
                let stale = store.snapshots.remove(oldest);
                store.snapshot_bytes -= stale.bytes;
            }
        }
        let page = self.snapshot_page(&snapshot, 0, store.recording);
        if retained {
            store.snapshot_bytes += snapshot.bytes;
            store.snapshots.push(snapshot);
        }
        Ok(page)
    }

    fn snapshot_page(&self, snapshot: &Snapshot, offset: usize, recording: bool) -> Value {
        let end = (offset + snapshot.filters.limit).min(snapshot.rows.len());
        json!({
            "instance_id": self.instance_id, "observed_at": snapshot.observed_at,
            "coverage": coverage(recording), "dropped_records": snapshot.dropped,
            "flows": &snapshot.rows[offset..end],
            "next_cursor": (end < snapshot.rows.len()).then(|| format!("{}.{}", snapshot.token, end))
        })
    }

    fn get(&self, flow_id: &str, id: &RequestId) -> Result<Value, ApiError> {
        let mut store = self.inner.lock();
        self.prune(&mut store, Instant::now());
        if let Some(record) = store.records.iter().find(|record| record.id() == flow_id) {
            return Ok(record.project(true, true));
        }
        if store
            .tombstones
            .iter()
            .any(|(expired, _)| expired == flow_id)
        {
            Err(error(
                StatusCode::GONE,
                ErrorCode::FlowExpired,
                "Flow retention expired",
                id,
            ))
        } else {
            Err(error(
                StatusCode::NOT_FOUND,
                ErrorCode::ResourceNotFound,
                "Flow not found",
                id,
            ))
        }
    }
}

impl Record {
    fn id(&self) -> &str {
        self.summary["id"].as_str().expect("record ID")
    }

    fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + value_heap_bytes(&self.summary)
            + value_heap_bytes(&self.input)
            + self.steps.capacity() * size_of::<Value>()
            + self.steps.iter().map(value_heap_bytes).sum::<usize>()
    }

    fn push_step(
        &mut self,
        stage: &'static str,
        generation_id: Option<String>,
        data: Value,
    ) -> bool {
        if self.steps.len() == MAX_STEPS {
            return !std::mem::replace(&mut self.overflow, true);
        }
        let elapsed = self.started.elapsed().as_micros();
        self.steps.push(json!({
            "seq": self.steps.len() + 1, "stage": stage,
            "observed_at": timestamp(SystemTime::now()),
            "elapsed_us": (elapsed <= u128::from(MAX_SAFE_UINT)).then_some(elapsed as u64),
            "generation_id": generation_id, "evidence": "observed", "data": data
        }));
        true
    }

    fn project(&self, full: bool, trace: bool) -> Value {
        let mut row = self.summary.clone();
        if full {
            row["input"] = self.input.clone();
        }
        if trace {
            let mut missing = vec!["not_instrumented"];
            if self.overflow {
                missing.push("buffer_overflow");
            }
            if self.redacted {
                missing.push("redacted");
            }
            row["trace"] = json!({"status": "partial", "missing": missing, "steps": self.steps});
        }
        row
    }
}

impl Filters {
    fn matches(&self, record: &Record) -> bool {
        (self.network == "all" || record.summary["network"] == self.network)
            && (self.state == "all" || record.summary["state"] == self.state)
            && self
                .connection_id
                .as_ref()
                .is_none_or(|id| record.summary["connection_id"] == *id)
    }
}

impl FlowGuard {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Returns true only for the first observed reply; callers need not record every packet.
    pub(crate) fn first_reply(&self) -> bool {
        !self.id.is_empty() && !self.replied.swap(true, Ordering::Relaxed)
    }

    pub(crate) fn step(&self, stage: &'static str, generation: Option<u64>, mut data: Value) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            if !complete_step(stage, &data) {
                return !std::mem::replace(&mut record.redacted, true);
            }
            let mut redacted = false;
            let mut overflow = false;
            if !sanitize_step(&mut data, 0, &mut 512, &mut redacted, &mut overflow) {
                return if overflow {
                    !std::mem::replace(&mut record.overflow, true)
                } else {
                    !std::mem::replace(&mut record.redacted, true)
                };
            }
            if value_heap_bytes(&data) > MAX_STEP_BYTES {
                return !std::mem::replace(&mut record.overflow, true);
            }
            let changed = redacted && !record.redacted;
            record.redacted |= redacted;
            record.push_step(
                stage,
                generation.map(|generation| format!("{}:{generation}", store.instance_id)),
                data,
            ) || changed
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn update_input(
        &self,
        domain: Option<&str>,
        source: Option<&'static str>,
        pname: Option<&str>,
        pid: Option<u32>,
        src_mac: Option<String>,
        dscp: Option<u8>,
        mark: Option<u32>,
    ) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            let mut redacted = record.redacted;
            let domain = safe_optional(domain, &mut redacted);
            let pname = safe_optional(pname, &mut redacted);
            let src_mac = safe_optional(src_mac.as_deref(), &mut redacted);
            let source = source.map(domain_source);
            let dscp = dscp.filter(|value| *value <= 63);
            let mut changed = record.redacted != redacted;
            record.redacted = redacted;
            for (key, value) in [
                ("domain", json!(domain)),
                ("domain_source", json!(source)),
                ("pid", json!(pid)),
                ("src_mac", json!(src_mac)),
                ("dscp", json!(dscp)),
                ("mark", json!(mark)),
            ] {
                if record.input[key] != value {
                    record.input[key] = value;
                    changed = true;
                }
            }
            if record.summary["pname"] != json!(pname) {
                record.summary["pname"] = json!(pname);
                changed = true;
            }
            if record.summary["domain_source"] != json!(source) {
                record.summary["domain_source"] = json!(source);
                changed = true;
            }
            let input_source = match source {
                Some("dns_mapping") => Some("dns_mapping"),
                Some("tls_sni" | "http_host" | "quic_sni") => Some("sniffer"),
                _ => None,
            };
            if changed && let Some(input_source) = input_source {
                let mut values = record.input.clone();
                values["pname"] = record.summary["pname"].clone();
                record.push_step(
                    "input",
                    None,
                    json!({"values": values, "source": input_source}),
                );
            }
            changed
        });
    }

    pub(crate) fn routed(
        &self,
        outbound: &str,
        rule_id: Option<&str>,
        expression: Option<&str>,
        source: &'static str,
    ) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            let mut redacted = record.redacted;
            let outbound = safe_optional(Some(outbound), &mut redacted);
            let rule_id = safe_optional(rule_id, &mut redacted);
            let expression = safe_optional(expression, &mut redacted);
            let source = rule_source(source);
            let changed = record.summary["outbound"] != json!(outbound)
                || record.summary["rule_id"] != json!(rule_id)
                || record.summary["rule_expression"] != json!(expression)
                || record.summary["rule_source"] != source
                || record.redacted != redacted;
            record.summary["outbound"] = json!(outbound);
            record.summary["rule_id"] = json!(rule_id);
            record.summary["rule_expression"] = json!(expression);
            record.summary["rule_source"] = json!(source);
            record.redacted = redacted;
            changed
        });
    }

    pub(crate) fn selected(&self, chain: Vec<String>) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            if chain.len() > MAX_STEPS || chain.iter().any(|part| !safe_text(part)) {
                return !std::mem::replace(&mut record.redacted, true);
            }
            let chain = json!(chain);
            if record.summary["chain"] == chain && record.summary["chain_source"] == "evaluation" {
                return false;
            }
            record.summary["chain"] = chain;
            record.summary["chain_source"] = json!("evaluation");
            true
        });
    }

    pub(crate) fn attach_connection(&self, id: &str) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            if !safe_text(id) {
                return !std::mem::replace(&mut record.redacted, true);
            }
            if record.summary["connection_id"] == id {
                return false;
            }
            record.summary["connection_id"] = json!(id);
            true
        });
    }

    pub(crate) fn transition(
        &self,
        state: &'static str,
        reason: &'static str,
        milestone: &'static str,
        reply_received: Option<bool>,
    ) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            let state = connection_state(state);
            let milestone = match milestone {
                "transport_ready"
                | "target_request_sent"
                | "target_confirmed"
                | "first_reply"
                | "terminal" => milestone,
                _ => "unknown",
            };
            let redacted = !safe_text(reason);
            let reason = if redacted { "redacted" } else { reason };
            let changed = record.summary["state"] != state
                || milestone == "terminal"
                || matches!(state, "closed" | "blocked" | "failed")
                || (redacted && !record.redacted);
            record.redacted |= redacted;
            record.summary["state"] = json!(state);
            if milestone == "terminal" || matches!(state, "closed" | "blocked" | "failed") {
                record.ended = Some(Instant::now());
                record.summary["ended_at"] = json!(timestamp(SystemTime::now()));
            }
            record.push_step(
                "connection",
                None,
                json!({
                    "state": state, "reason": reason, "milestone": milestone, "attempt_id": null,
                    "reply_received": reply_received, "error": null
                }),
            ) || changed
        });
    }

    pub(crate) fn finish(&self, state: &'static str, reason: &'static str) {
        let state = match state {
            "closed" | "blocked" | "failed" => state,
            _ => "unknown",
        };
        self.transition(
            state,
            reason,
            "terminal",
            self.replied.load(Ordering::Relaxed).then_some(true),
        );
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.finish("failed", "cancelled");
    }
}

pub(super) fn list(state: &NativeState, uri: &Uri, id: &RequestId) -> Result<Response, ApiError> {
    let query = parse_query(
        uri,
        &[
            "network",
            "state",
            "connection_id",
            "limit",
            "cursor",
            "detail",
        ],
        id,
    )?;
    let network = query.get("network").map(String::as_str).unwrap_or("all");
    let state_filter = query.get("state").map(String::as_str).unwrap_or("all");
    let limit = query
        .get("limit")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| invalid_query(id))?
        .unwrap_or(100);
    if !matches!(network, "tcp" | "udp" | "all")
        || !(state_filter == "all" || connection_state(state_filter) == state_filter)
        || !(1..=1000).contains(&limit)
        || query
            .get("connection_id")
            .is_some_and(|value| value.is_empty())
        || query.get("cursor").is_some_and(|value| value.is_empty())
    {
        return Err(invalid_query(id));
    }
    let filters = Filters {
        network: network.to_owned(),
        state: state_filter.to_owned(),
        connection_id: query.get("connection_id").cloned(),
        full: full_detail(&query, id)?,
        limit,
    };
    match state
        .observation
        .flows
        .page(filters, query.get("cursor").map(String::as_str), id)
    {
        Ok(page) => Ok(Json(page).into_response()),
        Err(error) => {
            let mut response = error.into_response();
            if response.status() == StatusCode::SERVICE_UNAVAILABLE {
                response
                    .headers_mut()
                    .insert("retry-after", axum::http::HeaderValue::from_static("1"));
            }
            Ok(response)
        }
    }
}

pub(super) fn detail(
    state: &NativeState,
    flow_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    Ok(Json(state.observation.flows.get(flow_id, id)?).into_response())
}

fn snapshot_expired(id: &RequestId) -> ApiError {
    error(
        StatusCode::GONE,
        ErrorCode::SnapshotExpired,
        "Flow snapshot expired",
        id,
    )
}

fn snapshot_busy(id: &RequestId) -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Flow snapshot capacity is full",
        id,
    )
}

fn coverage(recording: bool) -> Value {
    let userspace = if recording { "partial" } else { "none" };
    json!({"userspace_tcp": userspace, "userspace_udp": userspace, "kernel_direct": "none",
        "kernel_block": "none", "dns_intercept": "none", "kernel_bypass": "none"})
}

fn connection_state(value: &str) -> &'static str {
    match value {
        "observed" => "observed",
        "routing" => "routing",
        "dialing" => "dialing",
        "active" => "active",
        "closed" => "closed",
        "blocked" => "blocked",
        "failed" => "failed",
        _ => "unknown",
    }
}

fn domain_source(value: &str) -> &'static str {
    match value {
        "tls_sni" => "tls_sni",
        "http_host" => "http_host",
        "quic_sni" => "quic_sni",
        "dns_mapping" => "dns_mapping",
        "explicit" => "explicit",
        _ => "unknown",
    }
}

/// The wire vocabulary knows a kernel decision and userspace evidence. The
/// userspace connection paths name their route `evaluation`; that is the
/// recomputed kind, not an unknown one.
fn rule_source(value: &str) -> &'static str {
    match value {
        "kernel" => "kernel",
        "recomputed" | "evaluation" => "recomputed",
        _ => "unknown",
    }
}

fn safe_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | '@'))
}

fn safe_optional(value: Option<&str>, redacted: &mut bool) -> Option<String> {
    value.and_then(|value| {
        if safe_text(value) {
            Some(value.to_owned())
        } else {
            *redacted = true;
            None
        }
    })
}

fn complete_step(stage: &str, data: &Value) -> bool {
    let required: &[&str] = match stage {
        "input" => &["values", "source"],
        "route" => &[
            "evaluation_id",
            "chain",
            "plane",
            "rule_id",
            "rules",
            "outbound",
            "must",
            "mark",
            "input",
            "dns_action",
        ],
        "dial_mode" => &[
            "configured",
            "effective_target",
            "domain",
            "domain_source",
            "verification",
            "reason",
        ],
        "reroute" => &[
            "performed",
            "reason",
            "from_evaluation_id",
            "to_evaluation_id",
        ],
        "outbound" => &[
            "attempt_id",
            "parent_attempt_id",
            "kind",
            "evaluation_id",
            "routing_source",
            "routed_outbound",
            "effective_outbound",
            "mode_override",
            "selection_path",
            "leaf_node_id",
            "leaf_node_name",
            "target",
            "target_kind",
            "dial_ip",
            "server_addr",
            "resolution_location",
            "status",
            "error",
        ],
        "connection" => &[
            "state",
            "reason",
            "milestone",
            "attempt_id",
            "reply_received",
            "error",
        ],
        _ => return false,
    };
    data.as_object()
        .is_some_and(|data| required.iter().all(|key| data.contains_key(*key)))
}

fn sanitize_step(
    value: &mut Value,
    depth: usize,
    remaining: &mut usize,
    redacted: &mut bool,
    overflow: &mut bool,
) -> bool {
    if depth > 8 || *remaining == 0 {
        *overflow = true;
        return false;
    }
    *remaining -= 1;
    match value {
        Value::String(value) => safe_text(value),
        Value::Array(values) => {
            if values.len() > MAX_STEPS {
                *overflow = true;
                return false;
            }
            values
                .iter_mut()
                .all(|value| sanitize_step(value, depth + 1, remaining, redacted, overflow))
        }
        Value::Object(values) => {
            if values.len() > 32 {
                *overflow = true;
                return false;
            }
            for (key, value) in values.iter_mut() {
                let private_error = key == "error"
                    && !matches!(
                        value.as_str(),
                        Some(
                            "policy_block"
                                | "dial_failed"
                                | "dial_timeout"
                                | "local_refusal"
                                | "udp_prepare_failed"
                                | "runtime_generation_missing"
                                | "cancelled"
                        )
                    );
                let private_display = matches!(
                    key.as_str(),
                    "expression"
                        | "member_name"
                        | "leaf_node_name"
                        | "outbound"
                        | "routed_outbound"
                        | "effective_outbound"
                        | "pname"
                        | "domain"
                        | "src"
                        | "dst"
                        | "src_mac"
                        | "target"
                        | "server_addr"
                ) && value.as_str().is_some_and(|value| !safe_text(value));
                if (key == "process_path" || private_display || private_error) && !value.is_null() {
                    *value = Value::Null;
                    *redacted = true;
                }
                if !matches!(
                    key.as_str(),
                    "values"
                        | "source"
                        | "src"
                        | "dst"
                        | "domain"
                        | "domain_source"
                        | "pid"
                        | "process_path"
                        | "src_mac"
                        | "ingress"
                        | "domain_rule_ids"
                        | "dscp"
                        | "mark"
                        | "pname"
                        | "evaluation_id"
                        | "chain"
                        | "plane"
                        | "rule_id"
                        | "rules"
                        | "outbound"
                        | "must"
                        | "input"
                        | "dns_action"
                        | "network"
                        | "src_ip"
                        | "src_port"
                        | "dst_ip"
                        | "dst_port"
                        | "configured"
                        | "effective_target"
                        | "verification"
                        | "reason"
                        | "performed"
                        | "from_evaluation_id"
                        | "to_evaluation_id"
                        | "attempt_id"
                        | "parent_attempt_id"
                        | "kind"
                        | "routing_source"
                        | "routed_outbound"
                        | "effective_outbound"
                        | "mode_override"
                        | "selection_path"
                        | "leaf_node_id"
                        | "leaf_node_name"
                        | "target"
                        | "target_kind"
                        | "dial_ip"
                        | "server_addr"
                        | "resolution_location"
                        | "status"
                        | "error"
                        | "group_id"
                        | "member_id"
                        | "member_name"
                        | "policy"
                        | "selection"
                        | "previous_member_id"
                        | "metric"
                        | "tolerance_ms"
                        | "candidates"
                        | "eligible"
                        | "sorting_latency_ms"
                        | "score"
                        | "selected"
                        | "state"
                        | "milestone"
                        | "reply_received"
                        | "expression"
                        | "result"
                        | "missing_inputs"
                        | "conditions"
                        | "id"
                ) || !sanitize_step(value, depth + 1, remaining, redacted, overflow)
                {
                    return false;
                }
            }
            true
        }
        _ => true,
    }
}

// Conservative allocation accounting, not a temporary serialization buffer. The
// per-map allowance covers spare B-tree nodes; strings/arrays use owned capacity.
fn value_heap_bytes(value: &Value) -> usize {
    match value {
        Value::String(value) => value.capacity(),
        Value::Array(values) => {
            values.capacity() * size_of::<Value>()
                + values.iter().map(value_heap_bytes).sum::<usize>()
        }
        Value::Object(values) => {
            1024 + values
                .iter()
                .map(|(key, value)| 128 + key.capacity() + value_heap_bytes(value))
                .sum::<usize>()
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests;
