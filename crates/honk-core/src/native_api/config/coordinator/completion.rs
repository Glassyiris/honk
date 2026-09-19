use super::*;
use crate::configuration::{ActivationCompletion, ActivationFailure, ActivationRequest};
use crate::native_api::operations::OperationResult;

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

    pub(super) fn management_error(self) -> ApiError {
        let stage = match self {
            Self::Unconfirmed => "activation_unconfirmed",
            failure => failure.reason().0,
        };
        let committed = match self {
            Self::Unconfirmed => None,
            Self::Degraded(_) | Self::Reconciliation(_) => Some(true),
            _ => Some(false),
        };
        management::activation_error(stage, Some(true), Some(true), committed)
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
    ) {
        let pending = match self.activation.dispatch(request).await {
            Ok(pending) => pending,
            Err(failure) => {
                let error = match failure {
                    ActivationFailure::EngineUnavailable => {
                        unavailable().with_details(json!({"written":true}))
                    }
                    _ => unavailable(),
                };
                self.service.operations.reject(id, error);
                return;
            }
        };
        self.service.operations.accept(id);
        self.service.operations.running(id);
        let completion = self.activation.complete(pending).await;
        self.publish_operation(
            id,
            completion,
            group,
            Some(json!({"written":true,"committed":false})),
        );
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
                *self.service.last_reload.write() = Some(
                    json!({"operation_id":id,"status":"succeeded","finished_at":timestamp(SystemTime::now()),"error":null}),
                );
            }
        }
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
