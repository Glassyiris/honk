//! Bounded daemon operations. Reservation admission precedes coordinator side effects.

use std::{
    io::{self, Write},
    sync::{Arc, Weak},
    time::{Duration, SystemTime},
};

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{sync::watch, time::Instant};
use uuid::Uuid;

use super::{ApiError, ErrorCode, events::EventHub, timestamp};

const MAX_OPERATIONS: usize = 32;
const RETENTION: Duration = Duration::from_secs(300);
const MAX_ERROR_DETAILS: usize = 4096;
const MAX_RESULT_BYTES: usize = 262144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationKind {
    Reload,
    Probe,
    ProviderRefresh,
    GroupUpdate,
    Suspend,
    Resume,
    GeodataUpdate,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum OperationResult {
    Reload {
        active_generation_id: Option<String>,
        datapath_generation_id: Option<String>,
    },
    Probe(super::probes::ProbeResult),
    ProviderRefresh(super::providers::Provider),
    Geodata(super::geodata::GeoData),
    GroupUpdate {
        group_id: String,
        config_revision: String,
    },
    Suspend {
        runtime_state: &'static str,
    },
    Resume {
        runtime_state: &'static str,
    },
}

impl OperationResult {
    fn kind(&self) -> OperationKind {
        match self {
            Self::Reload { .. } => OperationKind::Reload,
            Self::Probe(_) => OperationKind::Probe,
            Self::ProviderRefresh(_) => OperationKind::ProviderRefresh,
            Self::Geodata(_) => OperationKind::GeodataUpdate,
            Self::GroupUpdate { .. } => OperationKind::GroupUpdate,
            Self::Suspend { .. } => OperationKind::Suspend,
            Self::Resume { .. } => OperationKind::Resume,
        }
    }
}

type Admission = Option<Result<OperationAcceptedResponse, ApiError>>;

pub(crate) struct OperationStore {
    instance_id: String,
    events: Arc<EventHub>,
    // ponytail: at most 32 entries; an index only helps if this ceiling grows.
    records: Mutex<Vec<Record>>,
}

struct Record {
    id: String,
    kind: OperationKind,
    replay: Option<Replay>,
    admission: watch::Sender<Admission>,
    operation: Option<Operation>,
    terminal_at: Option<Instant>,
}

struct Replay {
    scope: [u8; 32],
    body: [u8; 32],
}

struct Operation {
    status: Status,
    created_at: SystemTime,
    started_at: Option<SystemTime>,
    finished_at: Option<SystemTime>,
    result: Option<OperationResult>,
    error: Option<SafeError>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Serialize)]
struct SafeError {
    code: &'static str,
    message: &'static str,
    details: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct OperationAcceptedResponse {
    pub(crate) operation_id: String,
    pub(crate) kind: OperationKind,
    pub(crate) status: &'static str,
    pub(crate) href: String,
}

impl IntoResponse for OperationAcceptedResponse {
    fn into_response(self) -> Response {
        let location =
            HeaderValue::from_str(&self.href).expect("generated operation href is valid");
        let mut response = (
            StatusCode::ACCEPTED,
            [
                ("retry-after", "1"),
                ("cache-control", "no-store"),
                ("x-content-type-options", "nosniff"),
            ],
            Json(self),
        )
            .into_response();
        response.headers_mut().insert(header::LOCATION, location);
        response
    }
}

/// Move the fresh reservation into the daemon queue, not a request-owned task.
/// Dropping its preparation owner wakes all waiters without publishing an operation.
pub(crate) struct Reservation {
    pub(crate) id: String,
    pub(crate) fresh: bool,
    /// Who asked, as recorded in configuration revisions.
    pub(crate) principal: String,
    admission: watch::Receiver<Admission>,
    owner: Option<Weak<OperationStore>>,
}

impl Reservation {
    /// The returned future owns its receiver, so the reservation can move to the coordinator.
    pub(crate) fn admission(
        &self,
    ) -> impl Future<Output = Result<OperationAcceptedResponse, ApiError>> + Send + 'static + use<>
    {
        let mut receiver = self.admission.clone();
        async move {
            loop {
                if let Some(result) = receiver.borrow_and_update().clone() {
                    return result;
                }
                if receiver.changed().await.is_err() {
                    return Err(unavailable());
                }
            }
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.as_ref().and_then(Weak::upgrade) {
            owner.reject(&self.id, unavailable());
        }
    }
}

impl OperationStore {
    pub(crate) fn new(instance_id: String, events: Arc<EventHub>) -> Self {
        Self {
            instance_id,
            events,
            records: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        principal: &str,
        method: &str,
        path: &str,
        key: Option<&str>,
        body: &[u8],
        kind: OperationKind,
    ) -> Result<Reservation, ApiError> {
        let requester = principal.to_owned();
        if key == Some("") {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidRequest,
                "Idempotency-Key must not be empty.",
                None,
            ));
        }
        let principal = digest(&[self.instance_id.as_bytes(), principal.as_bytes()]);
        let replay = key.map(|key| {
            let scope = digest(&[
                self.instance_id.as_bytes(),
                &principal,
                method.as_bytes(),
                path.as_bytes(),
                key.as_bytes(),
            ]);
            Replay {
                body: digest(&[&scope, body]),
                scope,
            }
        });
        let mut records = self.records.lock();
        prune(&mut records);
        if let Some(replay) = &replay
            && let Some(record) = records.iter().find(|record| {
                record
                    .replay
                    .as_ref()
                    .is_some_and(|old| old.scope == replay.scope)
            })
        {
            if record
                .replay
                .as_ref()
                .is_some_and(|old| old.body != replay.body)
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::IdempotencyConflict,
                    "Idempotency-Key was already used with a different request body.",
                    None,
                ));
            }
            return Ok(Reservation {
                id: record.id.clone(),
                fresh: false,
                principal: requester,
                admission: record.admission.subscribe(),
                owner: None,
            });
        }
        if kind == OperationKind::GeodataUpdate
            && records
                .iter()
                .any(|record| record.kind == kind && record.terminal_at.is_none())
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::StateConflict,
                "A geodata update is already queued or running.",
                None,
            ));
        }
        if records.len() == MAX_OPERATIONS {
            return Err(unavailable());
        }
        let id = Uuid::new_v4().to_string();
        let (sender, receiver) = watch::channel(None);
        records.push(Record {
            id: id.clone(),
            kind,
            replay,
            admission: sender,
            operation: None,
            terminal_at: None,
        });
        Ok(Reservation {
            id,
            fresh: true,
            principal: requester,
            admission: receiver,
            owner: Some(Arc::downgrade(self)),
        })
    }

    /// Call only after durable source replacement (when needed) and real reload queue admission.
    pub(crate) fn accept(&self, id: &str) -> bool {
        let mut records = self.records.lock();
        let Some(record) = records.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        if record.operation.is_some() {
            return false;
        }
        record.operation = Some(Operation {
            status: Status::Queued,
            created_at: SystemTime::now(),
            started_at: None,
            finished_at: None,
            result: None,
            error: None,
        });
        self.publish(id, Status::Queued);
        record
            .admission
            .send_replace(Some(Ok(OperationAcceptedResponse {
                operation_id: id.into(),
                kind: record.kind,
                status: "queued",
                href: format!("/api/v1/operations/{id}"),
            })));
        true
    }

    pub(crate) fn reject(&self, id: &str, error: ApiError) -> bool {
        let mut records = self.records.lock();
        let Some(index) = records
            .iter()
            .position(|record| record.id == id && record.operation.is_none())
        else {
            return false;
        };
        let record = records.swap_remove(index);
        record.admission.send_replace(Some(Err(error)));
        true
    }

    pub(crate) fn running(&self, id: &str) -> bool {
        let mut records = self.records.lock();
        let Some(operation) = records
            .iter_mut()
            .find(|record| record.id == id)
            .and_then(|record| record.operation.as_mut())
        else {
            return false;
        };
        if operation.status != Status::Queued {
            return false;
        }
        operation.status = Status::Running;
        operation.started_at = Some(SystemTime::now());
        self.publish(id, Status::Running);
        true
    }

    pub(crate) fn succeed(&self, id: &str, result: OperationResult) -> bool {
        if serde_json::to_writer(DetailsBudget(MAX_RESULT_BYTES), &result).is_err() {
            return self.fail(
                id,
                "result_too_large",
                "Operation result exceeds its memory limit",
                None,
            );
        }
        self.finish(id, Ok(result), None)
    }

    /// Details must already be safe structured fields, not engine error strings or source text.
    pub(crate) fn fail(
        &self,
        id: &str,
        code: &'static str,
        message: &'static str,
        details: Option<Value>,
    ) -> bool {
        let details = details.filter(|value| {
            value.is_object()
                && serde_json::to_writer(DetailsBudget(MAX_ERROR_DETAILS), value).is_ok()
        });
        self.finish(
            id,
            Err(SafeError {
                code,
                message,
                details,
            }),
            None,
        )
    }

    /// Preserve completed measurement facts when lifecycle cleanup fails.
    pub(crate) fn fail_with_result(
        &self,
        id: &str,
        code: &'static str,
        message: &'static str,
        result: OperationResult,
    ) -> bool {
        let result = serde_json::to_writer(DetailsBudget(MAX_RESULT_BYTES), &result)
            .is_ok()
            .then_some(result);
        self.finish(
            id,
            Err(SafeError {
                code,
                message,
                details: None,
            }),
            result,
        )
    }

    fn finish(
        &self,
        id: &str,
        result: Result<OperationResult, SafeError>,
        failed_result: Option<OperationResult>,
    ) -> bool {
        let mut records = self.records.lock();
        let Some(record) = records.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        let Some(operation) = record.operation.as_mut() else {
            return false;
        };
        if record.terminal_at.is_some() || (result.is_ok() && operation.status != Status::Running) {
            return false;
        }
        let result = result.and_then(|result| {
            if result.kind() == record.kind {
                Ok(result)
            } else {
                Err(SafeError {
                    code: "invalid_operation_result",
                    message: "Operation result has an incompatible kind",
                    details: None,
                })
            }
        });
        match result {
            Ok(result) => {
                operation.status = Status::Succeeded;
                operation.result = Some(result);
            }
            Err(error) => {
                operation.status = Status::Failed;
                operation.error = Some(error);
                operation.result = failed_result.filter(|result| result.kind() == record.kind);
            }
        }
        operation.finished_at = Some(SystemTime::now());
        record.terminal_at = Some(Instant::now());
        self.publish(id, operation.status);
        true
    }

    pub(crate) fn get(&self, id: &str) -> Result<Response, ApiError> {
        let mut records = self.records.lock();
        prune(&mut records);
        let record = records.iter().find(|record| record.id == id);
        let (record, operation) = record
            .and_then(|record| {
                record
                    .operation
                    .as_ref()
                    .map(|operation| (record, operation))
            })
            .ok_or_else(not_found)?;
        let body = json!({
            "operation_id": record.id,
            "kind": record.kind,
            "status": operation.status,
            "created_at": timestamp(operation.created_at),
            "started_at": operation.started_at.map(timestamp),
            "finished_at": operation.finished_at.map(timestamp),
            "result": operation.result,
            "error": operation.error,
        });
        let mut response = (
            [
                ("cache-control", "no-store"),
                ("x-content-type-options", "nosniff"),
            ],
            Json(body),
        )
            .into_response();
        if record.terminal_at.is_none() {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        Ok(response)
    }

    fn publish(&self, id: &str, status: Status) {
        // Keep publication inside the state lock: concurrent transitions must not reorder events.
        self.events.publish(
            "operation.updated",
            json!({"resource_id": id, "status": status}),
            None,
        );
    }
}

fn prune(records: &mut Vec<Record>) {
    let now = Instant::now();
    records.retain(|record| {
        record
            .terminal_at
            .is_none_or(|terminal| now.duration_since(terminal) < RETENTION)
    });
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Operation admission is temporarily unavailable.",
        None,
    )
}

fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "The requested operation was not found.",
        None,
    )
}

struct DetailsBudget(usize);

impl Write for DetailsBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
