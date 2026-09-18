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
    let mut pending: FuturesUnordered<_> = selected
        .into_iter()
        .map(|selected| state.tracker.start_close(selected).wait())
        .collect();
    let (mut closed, mut skipped, mut uncertain) = (0usize, 0usize, false);
    while let Some(outcome) = pending.next().await {
        match outcome {
            CloseOutcome::Closed => closed += 1,
            CloseOutcome::NotClosable => skipped += 1,
            CloseOutcome::Gone => {}
            CloseOutcome::Failed => uncertain = true,
        }
    }
    if uncertain {
        return Err(failed(id));
    }
    Ok(Json(serde_json::json!({"closed":closed,"skipped":skipped})).into_response())
}
