//! Synchronous closure of exact userspace transport owners.

use axum::{
    Json,
    body::to_bytes,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::{StreamExt, stream::FuturesUnordered};
use std::net::IpAddr;

use super::{
    NativeState, error, invalid_query, parse_query,
    types::{ApiError, ErrorCode, RequestId},
};
use crate::connection_tracker::CloseOutcome;

pub(super) const MAX_BULK_CLOSE: usize = 1000;

async fn admit(request: Request, id: &RequestId) -> Result<(), ApiError> {
    if super::config::request_header(&request, "idempotency-key")
        .map_err(|error| error.with_request_id(id.0.clone()))?
        .is_some_and(str::is_empty)
    {
        return Err(invalid_query(id));
    }
    let body = to_bytes(request.into_body(), 65_536).await.map_err(|_| {
        error(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RequestTooLarge,
            "Request body exceeds its limit",
            id,
        )
    })?;
    if !body.is_empty() {
        return Err(invalid_query(id));
    }
    Ok(())
}

fn failed(id: &RequestId) -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Transport retirement could not be confirmed",
        id,
    )
}

pub(super) async fn close(
    state: &NativeState,
    connection_id: &str,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    admit(request, id).await?;
    match state.tracker.close_id(connection_id).await {
        CloseOutcome::Closed => Ok(StatusCode::NO_CONTENT.into_response()),
        CloseOutcome::Gone => Err(error(
            StatusCode::NOT_FOUND,
            ErrorCode::ResourceNotFound,
            "Connection not found",
            id,
        )),
        CloseOutcome::NotClosable => Err(error(
            StatusCode::CONFLICT,
            ErrorCode::StateConflict,
            "Connection is not owned by a closable userspace transport",
            id,
        )),
        CloseOutcome::Failed => Err(failed(id)),
    }
}

pub(super) async fn close_bulk(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let query = parse_query(request.uri(), &["type", "src", "all"], id)?;
    let network = match query.get("type").map(String::as_str).unwrap_or("all") {
        "all" => None,
        "tcp" => Some("tcp"),
        "udp" => Some("udp"),
        _ => return Err(invalid_query(id)),
    };
    let source = query
        .get("src")
        .map(|value| value.parse::<IpAddr>())
        .transpose()
        .map_err(|_| invalid_query(id))?;
    let all = match query.get("all").map(String::as_str).unwrap_or("false") {
        "true" => true,
        "false" => false,
        _ => return Err(invalid_query(id)),
    };
    if network.is_none() && source.is_none() && !all {
        return Err(invalid_query(id));
    }
    admit(request, id).await?;
    let selected = state
        .tracker
        .snapshot_close(network, source, MAX_BULK_CLOSE)
        .map_err(|()| {
            error(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::RequestTooLarge,
                "Too many matching connections",
                id,
            )
        })?;
    // All claims precede the first wait; HTTP cancellation cannot abandon a suffix.
    let outcomes: Vec<_> = selected
        .into_iter()
        .map(|selected| state.tracker.start_close(selected).wait())
        .collect::<FuturesUnordered<_>>()
        .collect()
        .await;
    bulk_result(outcomes, id)
}

/// A failed bulk close still reports its counts: those connections stay closed.
fn bulk_result(outcomes: Vec<CloseOutcome>, id: &RequestId) -> Result<Response, ApiError> {
    let (mut closed, mut skipped, mut uncertain) = (0usize, 0usize, false);
    for outcome in outcomes {
        match outcome {
            CloseOutcome::Closed => closed += 1,
            CloseOutcome::NotClosable => skipped += 1,
            CloseOutcome::Gone => {}
            CloseOutcome::Failed => uncertain = true,
        }
    }
    let counts = serde_json::json!({"closed":closed,"skipped":skipped});
    if uncertain {
        return Err(failed(id).with_details(counts));
    }
    Ok(Json(counts).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_bulk_close_reports_what_it_already_closed() {
        let id = RequestId("request-close".into());
        let response = bulk_result(
            vec![
                CloseOutcome::Closed,
                CloseOutcome::Failed,
                CloseOutcome::NotClosable,
                CloseOutcome::Closed,
                CloseOutcome::Gone,
            ],
            &id,
        )
        .unwrap_err()
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["retry-after"], "1");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "temporarily_unavailable");
        assert_eq!(
            body["error"]["details"],
            serde_json::json!({"closed": 2, "skipped": 1})
        );
    }
}
