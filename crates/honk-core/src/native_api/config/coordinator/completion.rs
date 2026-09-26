use super::*;
use crate::configuration::{ActivationCompletion, ActivationFailure, ActivationRequest};
use crate::native_api::operations::OperationResult;
use crate::native_api::store::Committed;

impl ActivationFailure {
    fn reason(self) -> (&'static str, &'static str) {
        match self {
            Self::RequestExhausted => ("request_exhausted", "Reload request sequence exhausted"),
            Self::EngineUnavailable => ("engine_unavailable", "Reload engine is unavailable"),
            Self::Unconfirmed => (
                "engine_unavailable",
                "Reload engine stopped before completion",
            ),
            Self::Rejected => ("reload_rejected", "Configuration reload was rejected"),
            Self::Degraded(_) => (
                "reload_degraded",
                "Configuration committed with degraded datapath",
            ),
            Self::Reconciliation(_) => (
                "supervisor_reconciliation_failed",
                "Configuration committed but worker reconciliation failed",
            ),
        }
    }

    pub(super) fn management_error(self, written: bool) -> ApiError {
        let stage = match self {
            Self::Unconfirmed => "activation_unconfirmed",
            failure => failure.reason().0,
        };
        let committed = match self {
            Self::Unconfirmed => None,
            Self::Degraded(_) | Self::Reconciliation(_) => Some(true),
            _ => Some(false),
        };
        management::activation_error(stage, Some(written), Some(written), committed)
    }
}

pub(super) fn log_sighup(completion: ActivationCompletion) {
    match completion {
        Ok(outcome) => tracing::info!(generation = outcome.generation(), "SIGHUP reload applied"),
        Err(ActivationFailure::Degraded(generation)) => {
            tracing::warn!(generation, "SIGHUP reload committed with degraded datapath")
        }
        Err(failure) => tracing::warn!(stage = failure.reason().0, "SIGHUP reload rejected"),
    }
}

impl Worker {
    pub(super) async fn replace_operation(
        &mut self,
        id: &str,
        request: ActivationRequest,
        group: Option<&str>,
        committed: Committed,
    ) {
        let written = committed.written();
        self.begin_record(&committed);
        let pending = match self.activation.dispatch(request).await {
            Ok(pending) => pending,
            Err(failure) => {
                let error = match failure {
                    ActivationFailure::EngineUnavailable => {
                        unavailable().with_details(json!({"written":written}))
                    }
                    _ => unavailable(),
                };
                self.service.operations.reject(id, error);
                *self.service.recording.write() = RecordState::Idle;
                return;
            }
        };
        self.service.operations.accept(id);
        self.service.operations.running(id);
        let completion = self.activation.complete(pending).await;
        let stored = match self.record(committed, &completion).await {
            Ok(stored) => stored,
            Err(details) => {
                let (code, message) = match completion {
                    Err(ActivationFailure::Unconfirmed) => ActivationFailure::Unconfirmed.reason(),
                    _ => (
                        "store_unavailable",
                        "Configuration is active but was not recorded",
                    ),
                };
                self.failed(id, code, message, Some(details));
                return;
            }
        };
        self.publish_operation(
            id,
            completion,
            group,
            Some(json!({"written":stored,"committed":false})),
        );
    }

    pub(super) fn begin_record(&self, committed: &Committed) {
        if !committed.written() {
            let revision = self.service.sources.revision();
            *self.service.recording.write() = RecordState::Pending(revision);
        }
    }

    /// Records an activated candidate in the store. `Ok` says whether the store
    /// now holds the candidate; `Err` carries the failure details.
    pub(super) async fn record(
        &self,
        committed: Committed,
        completion: &ActivationCompletion,
    ) -> Result<bool, Value> {
        if committed.written() {
            return Ok(true);
        }
        let Some(store) = &self.store else {
            return Ok(false);
        };
        let result = match completion {
            Ok(_) | Err(ActivationFailure::Degraded(_) | ActivationFailure::Reconciliation(_)) => {
                let writer = Arc::clone(store);
                match tokio::task::spawn_blocking(move || writer.promote(committed)).await {
                    Ok(Ok(())) => Ok(true),
                    _ => {
                        store.block();
                        Err(json!({"stage":"store","committed":true,"durable":false}))
                    }
                }
            }
            Err(ActivationFailure::Unconfirmed) => {
                store.block();
                Err(json!({"stage":"store","committed":null}))
            }
            Err(_) => Ok(false),
        };
        *self.service.recording.write() = RecordState::Idle;
        result
    }

    pub(super) async fn reload_operation(&mut self, id: &str, request: ActivationRequest) {
        let completion = self.activation.activate(request).await;
        self.publish_operation(id, completion, None, None);
    }

    fn publish_operation(
        &self,
        id: &str,
        completion: ActivationCompletion,
        group: Option<&str>,
        rejected_details: Option<Value>,
    ) {
        match completion {
            Err(failure) => {
                let details = match failure {
                    ActivationFailure::Rejected => rejected_details,
                    ActivationFailure::Degraded(generation) => Some(
                        json!({"active_generation_id":format!("{}:{generation}",self.service.instance_id),"committed":true}),
                    ),
                    ActivationFailure::Reconciliation(generation) => Some(
                        json!({"active_generation_id":generation.map(|generation|format!("{}:{generation}",self.service.instance_id)),"committed":true}),
                    ),
                    _ => None,
                };
                let (code, message) = failure.reason();
                self.failed(id, code, message, details);
            }
            Ok(outcome) => {
                let result = if let Some(group_id) = group {
                    let Some(config_revision) = self.service.sources.revision() else {
                        self.failed(
                            id,
                            "source_authority_lost",
                            "Group committed without retained source authority",
                            None,
                        );
                        return;
                    };
                    OperationResult::GroupUpdate {
                        group_id: group_id.to_owned(),
                        config_revision,
                    }
                } else {
                    OperationResult::Reload {
                        active_generation_id: outcome
                            .generation()
                            .map(|generation| format!("{}:{generation}", self.service.instance_id)),
                        datapath_generation_id: None,
                    }
                };
                self.service.operations.succeed(id, result);
                self.reloaded(id);
            }
        }
    }

    pub(super) fn reloaded(&self, id: &str) {
        *self.service.last_reload.write() = Some(
            json!({"operation_id":id,"status":"succeeded","finished_at":timestamp(SystemTime::now()),"error":null}),
        );
    }

    pub(super) fn failed(
        &self,
        id: &str,
        code: &'static str,
        message: &'static str,
        details: Option<Value>,
    ) {
        self.service
            .operations
            .fail(id, code, message, details.clone());
        *self.service.last_reload.write() = Some(
            json!({"operation_id":id,"status":"failed","finished_at":timestamp(SystemTime::now()),"error":{"code":code,"message":message,"details":details}}),
        );
    }

    pub(super) fn lifecycle_error(
        &self,
        error: crate::control::client::ControlError,
        before: u64,
    ) -> ApiError {
        if matches!(error, crate::control::client::ControlError::StateConflict) {
            return ApiError::new(
                StatusCode::CONFLICT,
                ErrorCode::StateConflict,
                "Runtime transition conflicts with the current state",
                None,
            );
        }
        let error = ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::TemporarilyUnavailable,
            "Runtime transition could not be completed",
            None,
        );
        let generation = self.diagnostics.read().generation;
        if generation != before {
            error.with_details(json!({"committed":true,"active_generation_id":format!("{}:{generation}",self.service.instance_id)}))
        } else {
            error
        }
    }
}
