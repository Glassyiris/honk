//! Bounded process-local invalidations. Replay and live attachment share one lock.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use futures::{Stream, task::AtomicWaker};
use hkdf::Hkdf;
use parking_lot::Mutex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use uuid::Uuid;

use super::{ApiError, ErrorCode, NativeState, error, parse_query, timestamp, types::RequestId};

const MAX_EVENTS: usize = 512;
const MAX_CLIENTS: usize = 16;
const CLIENT_QUEUE: usize = 64;
const MAX_PAYLOAD_BYTES: usize = 4096;
const RETENTION: Duration = Duration::from_secs(60);
const HEARTBEAT: Duration = Duration::from_secs(15);
const MAX_SAFE_UINT: u64 = 9_007_199_254_740_991;
const KINDS: [&str; 6] = [
    "stream.ready",
    "runtime.updated",
    "flow.updated",
    "flow.gap",
    "operation.updated",
    "generation.changed",
];

#[derive(Clone)]
struct Filter {
    kinds: u8,
    flow_id: Option<String>,
    binding: [u8; 32],
}

impl Filter {
    fn new(kinds: u8, flow_id: Option<String>) -> Self {
        let mut hash = Sha256::new();
        hash.update([kinds, u8::from(flow_id.is_some())]);
        if let Some(id) = &flow_id {
            hash.update(id.as_bytes());
        }
        Self {
            kinds,
            flow_id,
            binding: hash.finalize().into(),
        }
    }

    fn matches(&self, record: &Record) -> bool {
        self.kinds & (1 << record.kind) != 0
            && (!matches!(record.kind, 2 | 3)
                || self.flow_id.is_none()
                || self.flow_id.as_deref() == record.flow_id.as_deref())
    }
}

struct Record {
    seq: u64,
    stamp: u64,
    nonce: [u8; 16],
    created: Instant,
    kind: usize,
    flow_id: Option<String>,
    payload: Bytes,
}

struct Subscriber {
    filter: Filter,
    queue: VecDeque<Arc<Record>>,
    closed: bool,
    waker: AtomicWaker,
}

impl Subscriber {
    fn close(&mut self) {
        self.closed = true;
        self.queue.clear();
        self.waker.wake();
    }
}

struct State {
    records: VecDeque<Arc<Record>>,
    subscribers: [Option<Subscriber>; MAX_CLIENTS],
    sequence: u64,
    evicted_through: u64,
    signer: Hkdf<Sha256>,
    stopped: bool,
}

impl State {
    fn prune(&mut self, now: Instant) {
        while self
            .records
            .front()
            .is_some_and(|record| now.duration_since(record.created) >= RETENTION)
        {
            self.evict();
        }
    }

    fn evict(&mut self) {
        if let Some(record) = self.records.pop_front() {
            self.evicted_through = record.seq;
        }
    }

    fn close_clients(&mut self) {
        for subscriber in self.subscribers.iter_mut().flatten() {
            subscriber.close();
        }
    }
}

pub(crate) struct EventHub {
    instance_id: String,
    started: Instant,
    state: Mutex<State>,
}

impl EventHub {
    pub(crate) fn new(instance_id: String) -> Self {
        assert!(
            !instance_id.is_empty() && instance_id.len() <= 256,
            "invalid native instance ID"
        );
        let signer = new_signer(&instance_id);
        Self {
            instance_id,
            started: Instant::now(),
            state: Mutex::new(State {
                records: VecDeque::new(),
                subscribers: std::array::from_fn(|_| None),
                sequence: 0,
                evicted_through: 0,
                signer,
                stopped: false,
            }),
        }
    }

    /// Producers supply only schema fields, never raw errors or configuration.
    pub(crate) fn publish(&self, kind: &'static str, data: Value, flow_id: Option<&str>) {
        let payload = self.payload(kind, &data, flow_id);
        let mut state = self.state.lock();
        if state.stopped {
            return;
        }
        let now = Instant::now();
        state.prune(now);
        let Some((kind, payload)) = payload else {
            // A refused notification is a replay discontinuity, not a silent skip.
            state.close_clients();
            state.records.clear();
            state.evicted_through = state.sequence;
            state.signer = new_signer(&self.instance_id);
            return;
        };
        let Some(sequence) = state.sequence.checked_add(1) else {
            state.stopped = true;
            state.close_clients();
            return;
        };
        let Ok(stamp) = u64::try_from(now.duration_since(self.started).as_nanos()) else {
            state.stopped = true;
            state.close_clients();
            return;
        };
        state.sequence = sequence;
        let record = Arc::new(Record {
            seq: sequence,
            stamp,
            nonce: *Uuid::new_v4().as_bytes(),
            created: now,
            kind,
            flow_id: flow_id.map(str::to_owned),
            payload,
        });
        if state.records.len() == MAX_EVENTS {
            state.evict();
        }
        state.records.push_back(Arc::clone(&record));
        for subscriber in state.subscribers.iter_mut().flatten() {
            if subscriber.closed || !subscriber.filter.matches(&record) {
                continue;
            }
            if subscriber.queue.len() == CLIENT_QUEUE {
                subscriber.close();
            } else {
                subscriber.queue.push_back(Arc::clone(&record));
                subscriber.waker.wake();
            }
        }
    }

    /// Test seam: the kinds of the buffered notifications, oldest first.
    #[cfg(test)]
    pub(crate) fn buffered_kinds(&self) -> Vec<&'static str> {
        let state = self.state.lock();
        state
            .records
            .iter()
            .map(|record| KINDS[record.kind])
            .collect()
    }

    pub(crate) fn shutdown(&self) {
        let mut state = self.state.lock();
        state.stopped = true;
        state.close_clients();
        state.records.clear();
    }

    fn payload(&self, kind: &str, data: &Value, flow_id: Option<&str>) -> Option<(usize, Bytes)> {
        let kind = KINDS.iter().position(|candidate| *candidate == kind)?;
        let mut payload = json!({
            "instance_id": self.instance_id,
            "observed_at": timestamp(SystemTime::now()),
        });
        let object = payload.as_object_mut()?;
        match kind {
            1 if flow_id.is_none() => {
                object.insert("href".into(), json!("/api/v1/runtime"));
            }
            2 => {
                let id = identifier(data.get("resource_id")?)?;
                let revision = data.get("revision")?.as_u64()?;
                if flow_id != Some(id) || !(1..=MAX_SAFE_UINT).contains(&revision) {
                    return None;
                }
                object.insert("resource_id".into(), json!(id));
                object.insert("revision".into(), json!(revision));
                object.insert("href".into(), json!(format!("/api/v1/flows/{id}")));
            }
            3 => {
                let resource = data.get("resource_id")?;
                let id = if resource.is_null() {
                    None
                } else {
                    Some(identifier(resource)?)
                };
                let reason = data.get("reason")?.as_str()?;
                let dropped = data.get("dropped_records")?;
                if id != flow_id
                    || !["buffer_overflow", "sampled", "evicted", "recording_changed"]
                        .contains(&reason)
                    || !nullable_uint64(dropped)
                {
                    return None;
                }
                object.insert("resource_id".into(), json!(id));
                object.insert("reason".into(), json!(reason));
                object.insert("dropped_records".into(), dropped.clone());
            }
            4 if flow_id.is_none() => {
                let id = identifier(data.get("resource_id")?)?;
                let status = data.get("status")?.as_str()?;
                if !["queued", "running", "succeeded", "failed"].contains(&status) {
                    return None;
                }
                object.insert("resource_id".into(), json!(id));
                object.insert("status".into(), json!(status));
                object.insert("href".into(), json!(format!("/api/v1/operations/{id}")));
            }
            5 if flow_id.is_none() => {
                for field in ["previous_generation_id", "generation_id"] {
                    object.insert(field.into(), json!(identifier(data.get(field)?)?));
                }
            }
            _ => return None,
        }
        let bytes = serde_json::to_vec(&payload).ok()?;
        (bytes.len() <= MAX_PAYLOAD_BYTES).then(|| (kind, Bytes::from(bytes)))
    }

    fn subscribe(
        self: &Arc<Self>,
        filter: Filter,
        cursor: Option<&str>,
        id: &RequestId,
    ) -> Result<Subscription, ApiError> {
        let mut state = self.state.lock();
        let now = Instant::now();
        state.prune(now);
        let cutoff = state.sequence;
        let replay = cursor
            .map(|cursor| self.resume_sequence(&state, cursor, &filter, now, id))
            .transpose()?
            .map(|after| (after, cutoff));
        if state.stopped {
            return Err(error(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::TemporarilyUnavailable,
                "Event stream is unavailable",
                id,
            ));
        }
        let slot = state
            .subscribers
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| {
                error(
                    StatusCode::TOO_MANY_REQUESTS,
                    ErrorCode::RateLimited,
                    "Event subscriber limit reached",
                    id,
                )
            })?;
        let stamp =
            u64::try_from(now.duration_since(self.started).as_nanos()).map_err(|_| expired(id))?;
        let ready_id = encode_cursor(
            &state.signer,
            cutoff,
            stamp,
            Uuid::new_v4().as_bytes(),
            &filter.binding,
        );
        let ready = frame(
            "stream.ready",
            &ready_id,
            &serde_json::to_vec(&json!({
                "instance_id": self.instance_id,
                "observed_at": timestamp(SystemTime::now()),
            }))
            .expect("event data is serializable"),
        );
        state.subscribers[slot] = Some(Subscriber {
            filter,
            queue: VecDeque::new(),
            closed: false,
            waker: AtomicWaker::new(),
        });
        let mut heartbeat = tokio::time::interval_at(now + HEARTBEAT, HEARTBEAT);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Ok(Subscription {
            hub: Arc::clone(self),
            slot,
            replay,
            ready: Some(ready),
            heartbeat,
            ended: false,
        })
    }

    fn resume_sequence(
        &self,
        state: &State,
        cursor: &str,
        filter: &Filter,
        now: Instant,
        id: &RequestId,
    ) -> Result<u64, ApiError> {
        let mut bytes = [0u8; 96];
        if cursor.len() != 128 || URL_SAFE_NO_PAD.decode_slice(cursor, &mut bytes) != Ok(96) {
            return Err(expired(id));
        }
        let mut signature = [0u8; 32];
        state
            .signer
            .expand(&bytes[..64], &mut signature)
            .expect("fixed HKDF length");
        let seq = u64::from_be_bytes(bytes[..8].try_into().expect("fixed cursor length"));
        let stamp = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed cursor length"));
        let age = now
            .duration_since(self.started)
            .as_nanos()
            .checked_sub(u128::from(stamp));
        if signature.ct_eq(&bytes[64..]).unwrap_u8() != 1
            || bytes[32..64] != filter.binding
            || seq > state.sequence
            || (state.evicted_through != 0 && seq <= state.evicted_through)
            || age.is_none_or(|age| age >= RETENTION.as_nanos())
        {
            return Err(expired(id));
        }
        Ok(seq)
    }
}

struct Subscription {
    hub: Arc<EventHub>,
    slot: usize,
    replay: Option<(u64, u64)>,
    ready: Option<Bytes>,
    heartbeat: Interval,
    ended: bool,
}

impl Stream for Subscription {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        let mut state = this.hub.state.lock();
        let now = Instant::now();
        state.prune(now);
        let closed = state.subscribers[this.slot]
            .as_ref()
            .is_none_or(|sub| sub.closed);
        let replay_lost = this
            .replay
            .is_some_and(|(after, cutoff)| after < cutoff && state.evicted_through > after);
        if closed || replay_lost {
            if let Some(subscriber) = &mut state.subscribers[this.slot] {
                subscriber.close();
            }
            this.ended = true;
            this.ready = None;
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "event subscription ended",
            ))));
        }
        if let Some((after, cutoff)) = this.replay {
            let filter = &state.subscribers[this.slot]
                .as_ref()
                .expect("live subscriber")
                .filter;
            if let Some(record) = state
                .records
                .iter()
                .find(|record| record.seq > after && record.seq <= cutoff && filter.matches(record))
            {
                this.replay = Some((record.seq, cutoff));
                return Poll::Ready(Some(Ok(record_frame(&state.signer, record, filter))));
            }
            this.replay = None;
        }
        if let Some(ready) = this.ready.take() {
            return Poll::Ready(Some(Ok(ready)));
        }
        let subscriber = state.subscribers[this.slot]
            .as_mut()
            .expect("live subscriber");
        if let Some(record) = subscriber.queue.pop_front() {
            if now.duration_since(record.created) >= RETENTION {
                subscriber.close();
                this.ended = true;
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "event subscription ended",
                ))));
            }
            return Poll::Ready(Some(Ok(record_frame(
                &state.signer,
                &record,
                &state.subscribers[this.slot]
                    .as_ref()
                    .expect("live subscriber")
                    .filter,
            ))));
        }
        subscriber.waker.register(cx.waker());
        drop(state);
        this.heartbeat
            .poll_tick(cx)
            .map(|_| Some(Ok(Bytes::from_static(b": heartbeat\n\n"))))
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.hub.state.lock().subscribers[self.slot] = None;
    }
}

fn new_signer(instance_id: &str) -> Hkdf<Sha256> {
    Hkdf::<Sha256>::new(Some(instance_id.as_bytes()), Uuid::new_v4().as_bytes())
}

fn encode_cursor(
    signer: &Hkdf<Sha256>,
    seq: u64,
    stamp: u64,
    nonce: &[u8; 16],
    binding: &[u8; 32],
) -> String {
    let mut bytes = [0u8; 96];
    bytes[..8].copy_from_slice(&seq.to_be_bytes());
    bytes[8..16].copy_from_slice(&stamp.to_be_bytes());
    bytes[16..32].copy_from_slice(nonce);
    bytes[32..64].copy_from_slice(binding);
    let (input, tag) = bytes.split_at_mut(64);
    signer.expand(input, tag).expect("fixed HKDF length");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn record_frame(signer: &Hkdf<Sha256>, record: &Record, filter: &Filter) -> Bytes {
    let cursor = encode_cursor(
        signer,
        record.seq,
        record.stamp,
        &record.nonce,
        &filter.binding,
    );
    frame(KINDS[record.kind], &cursor, &record.payload)
}

fn frame(kind: &str, cursor: &str, payload: &[u8]) -> Bytes {
    let mut bytes = Vec::with_capacity(kind.len() + cursor.len() + payload.len() + 22);
    bytes.extend_from_slice(b"event: ");
    bytes.extend_from_slice(kind.as_bytes());
    bytes.extend_from_slice(b"\nid: ");
    bytes.extend_from_slice(cursor.as_bytes());
    bytes.extend_from_slice(b"\ndata: ");
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(b"\n\n");
    Bytes::from(bytes)
}

fn identifier(value: &Value) -> Option<&str> {
    let id = value.as_str()?;
    (!id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte)))
    .then_some(id)
}

fn nullable_uint64(value: &Value) -> bool {
    value.is_null()
        || value.as_str().is_some_and(|value| {
            !value.is_empty()
                && value.len() <= 20
                && (value == "0" || !value.starts_with('0'))
                && value.bytes().all(|byte| byte.is_ascii_digit())
                && value.parse::<u64>().is_ok()
        })
}

fn expired(id: &RequestId) -> ApiError {
    error(
        StatusCode::CONFLICT,
        ErrorCode::EventCursorExpired,
        "Event cursor expired; reconnect without it",
        id,
    )
}

fn invalid(id: &RequestId) -> ApiError {
    error(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid event stream request",
        id,
    )
}

fn request_options(
    request: &Request,
    id: &RequestId,
) -> Result<(Filter, Option<String>), ApiError> {
    let values = parse_query(request.uri(), &["kinds", "flow_id"], id)?;
    let kinds = if let Some(kinds) = values.get("kinds") {
        let mut mask = 0;
        for kind in kinds.split(',') {
            let bit = KINDS
                .iter()
                .position(|candidate| *candidate == kind)
                .ok_or_else(|| invalid(id))?;
            if mask & (1 << bit) != 0 {
                return Err(invalid(id));
            }
            mask |= 1 << bit;
        }
        mask
    } else {
        (1 << KINDS.len()) - 1
    };
    let flow_id = values.get("flow_id").cloned();
    if flow_id.as_ref().is_some_and(|flow_id| {
        flow_id.is_empty() || flow_id.len() > 256 || flow_id.chars().any(char::is_control)
    }) || !accepts_events(request.headers())
    {
        return Err(invalid(id));
    }
    let mut cursors = request.headers().get_all("last-event-id").iter();
    let cursor = cursors
        .next()
        .map(|value| value.to_str().map(str::to_owned).map_err(|_| invalid(id)))
        .transpose()?;
    if cursors.next().is_some() || cursor.as_ref().is_some_and(String::is_empty) {
        return Err(invalid(id));
    }
    Ok((Filter::new(kinds, flow_id), cursor))
}

fn accepts_events(headers: &HeaderMap) -> bool {
    if !headers.contains_key(header::ACCEPT) {
        return true;
    }
    let mut best = None;
    for value in headers.get_all(header::ACCEPT) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for range in value.split(',') {
            let mut parts = range.trim().split(';');
            let media = parts.next().unwrap_or_default().trim();
            let Some((kind, subtype)) = media.split_once('/') else {
                return false;
            };
            if !token(kind) || !token(subtype) || (kind == "*" && subtype != "*") {
                return false;
            }
            let mut specificity = if media.eq_ignore_ascii_case("text/event-stream") {
                Some(2)
            } else if media.eq_ignore_ascii_case("text/*") {
                Some(1)
            } else if media == "*/*" {
                Some(0)
            } else {
                None
            };
            let mut quality = 1000;
            let mut seen_quality = false;
            for parameter in parts {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    return false;
                };
                let (name, value) = (name.trim(), value.trim());
                if name.eq_ignore_ascii_case("q") {
                    let Some(parsed) = quality_value(value) else {
                        return false;
                    };
                    if seen_quality {
                        return false;
                    }
                    seen_quality = true;
                    quality = parsed;
                } else {
                    let value = value
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .unwrap_or(value);
                    if !token(name) || !token(value) {
                        return false;
                    }
                    if !name.eq_ignore_ascii_case("charset") || !value.eq_ignore_ascii_case("utf-8")
                    {
                        specificity = None;
                    }
                }
            }
            if let Some(specificity) = specificity
                && best.is_none_or(|(rank, q)| {
                    specificity > rank || (specificity == rank && quality > q)
                })
            {
                best = Some((specificity, quality));
            }
        }
    }
    best.is_some_and(|(_, quality)| quality > 0)
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn quality_value(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if !matches!(whole, "0" | "1")
        || fraction.len() > 3
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let fraction = fraction
        .bytes()
        .fold(0u16, |value, byte| value * 10 + u16::from(byte - b'0'))
        * 10u16.pow(3 - fraction.len() as u32);
    match whole {
        "0" => Some(fraction),
        "1" if fraction == 0 => Some(1000),
        _ => None,
    }
}

pub(super) async fn serve(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let (filter, cursor) = request_options(&request, id)?;
    let subscription = state
        .observation
        .events
        .subscribe(filter, cursor.as_deref(), id)?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-store"),
            (
                header::HeaderName::from_static("x-content-type-options"),
                "nosniff",
            ),
            (header::HeaderName::from_static("x-accel-buffering"), "no"),
        ],
        Body::from_stream(subscription),
    )
        .into_response())
}

#[cfg(test)]
mod tests;
