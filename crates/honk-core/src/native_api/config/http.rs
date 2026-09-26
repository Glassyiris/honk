//! HTTP adapters for source reads, validation and coordinator admission.

use super::*;

fn if_match(request: &Request) -> Result<String, ApiError> {
    let tag = request_header(request, "if-match")?.ok_or_else(|| {
        ApiError::new(
            StatusCode::PRECONDITION_REQUIRED,
            ErrorCode::PreconditionRequired,
            "A strong source revision is required",
            None,
        )
    })?;
    let hash = tag
        .strip_prefix('"')
        .and_then(|tag| tag.strip_suffix('"'))
        .filter(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(invalid)?;
    Ok(hash.to_owned())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    content: String,
    #[serde(default, rename = "secrets_redacted")]
    _secrets_redacted: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Creation {
    path: String,
    content: String,
}

pub(in crate::native_api) fn administrative_projection(
    state: &NativeState,
    mut value: Value,
) -> Result<Value, ApiError> {
    let accepted = state.observation.configuration.sources.accepted.read();
    let secrets = state
        .observation
        .configuration
        .secrets(accepted.as_ref())
        .as_ref()
        .clone()
        .with_clash(&state.clash_secret);
    secrets.mask_value(&mut value);
    Ok(value)
}

pub(in crate::native_api) async fn get(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let _config = state.config.read().await;
    let store = state.observation.configuration.store_value();
    let mut value = state.observation.configuration.snapshot().ok_or_else(|| {
        error(
            StatusCode::NOT_FOUND,
            ErrorCode::CapabilityNotSupported,
            "Configuration sources are unavailable",
            id,
        )
    })?;
    let accepted = state.observation.configuration.sources.accepted.read();
    let accepted = accepted
        .as_ref()
        .expect("source snapshot pinned by config publication guard");
    let active = state.diagnostics.read();
    value["generation_id"] = json!(format!("{}:{}", state.instance_id, active.generation));
    value["store"] = store;
    let diagnostics = active
        .buckets
        .static_diagnostics
        .iter()
        .chain(active.buckets.providers.iter().flat_map(|(_, rows)| rows));
    value["diagnostics"] = json!(
        diagnostics
            .map(|diagnostic| project_diagnostic(
                diagnostic,
                &accepted.update.sources,
                &accepted.ids,
                None
            ))
            .collect::<Vec<_>>()
    );
    Ok(Json(value).into_response())
}

pub(in crate::native_api) async fn source(
    state: &NativeState,
    source_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let _config = state.config.read().await;
    let accepted = state.observation.configuration.sources.accepted.read();
    let accepted = accepted.as_ref().ok_or_else(unsupported)?;
    let index = accepted
        .update
        .sources
        .iter()
        .position(|source| accepted.ids[&source.path] == source_id)
        .ok_or_else(not_found)?;
    let secrets = state.observation.configuration.secrets(Some(accepted));
    Ok(Json(
        state
            .observation
            .configuration
            .source_value(accepted, index, &secrets)
            .0,
    )
    .into_response())
}

pub(in crate::native_api) async fn replace(
    state: &NativeState,
    source_id: String,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    if !state.observation.configuration.sources.available() {
        return Err(unsupported());
    }
    if !state.observation.configuration.writable() {
        return Err(denied());
    }
    let expected = if_match(&request)?;
    json_type(&request)?;
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    let path = request.uri().path().to_owned();
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    let replacement: Replacement = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let reservation = state.observation.configuration.operations.reserve(
        state.principal(),
        "PUT",
        &path,
        key.as_deref(),
        &bytes,
        crate::native_api::operations::OperationKind::Reload,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        state.observation.configuration.enqueue(Work::Replace {
            source_id,
            content: replacement.content,
            if_match: expected,
            reservation,
        })?;
    }
    Ok(admission.await?.into_response())
}

pub(in crate::native_api) async fn create(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    if !state.observation.configuration.sources.available() {
        return Err(unsupported());
    }
    if !state.observation.configuration.writable() {
        return Err(denied());
    }
    // A blocked store advertises `create: false`.
    if !state.observation.configuration.editable() {
        return Err(unsupported());
    }
    json_type(&request)?;
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    let creation: Creation = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if !new_source_path(&creation.path) {
        return Err(invalid());
    }
    let reservation = state.observation.configuration.operations.reserve(
        state.principal(),
        "POST",
        "/api/v1/config/sources",
        key.as_deref(),
        &bytes,
        crate::native_api::operations::OperationKind::Reload,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        state.observation.configuration.enqueue(Work::Create {
            path: creation.path,
            content: creation.content,
            reservation,
        })?;
    }
    Ok(admission.await?.into_response())
}

pub(in crate::native_api) async fn reload(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    if !state.observation.configuration.running() {
        return Err(unsupported());
    }
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    let has_body = request.body().size_hint().upper() != Some(0);
    if has_body {
        json_type(&request)?;
    }
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    if !bytes.is_empty() {
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if !value.as_object().is_some_and(|object| object.is_empty()) {
            return Err(invalid());
        }
    }
    let reservation = state.observation.configuration.operations.reserve(
        state.principal(),
        "POST",
        "/api/v1/operations/reload",
        key.as_deref(),
        &bytes,
        crate::native_api::operations::OperationKind::Reload,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        state
            .observation
            .configuration
            .enqueue(Work::Reload { reservation })?;
    }
    Ok(admission.await?.into_response())
}

pub(in crate::native_api) async fn validate(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    if !state.observation.configuration.running() {
        return Err(unsupported());
    }
    parse_query(request.uri(), &[], id)?;
    json_type(&request)?;
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    let request: ValidationRequest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.sources.is_empty() || request.sources.len() > MAX_SOURCES {
        return Err(if request.sources.is_empty() {
            invalid()
        } else {
            too_large()
        });
    }
    if !matches!(request.mode.as_str(), "syntax" | "full") {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::UnsupportedValue,
            "Validation mode is not supported",
            None,
        ));
    }
    let mut seen = HashSet::new();
    let mut paths = HashSet::new();
    let mut total = 0usize;
    for (index, source) in request.sources.iter().enumerate() {
        let name = source
            .id
            .clone()
            .unwrap_or_else(|| format!("source-{}", index + 1));
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || !seen.insert(name)
        {
            return Err(invalid());
        }
        if let Some(path) = &source.path
            && (path.is_empty() || !paths.insert(path))
        {
            return Err(invalid());
        }
        total = total
            .checked_add(source.content.len())
            .ok_or_else(too_large)?;
    }
    if total > MAX_SOURCE_BYTES {
        return Err(too_large());
    }
    let (response, result) = oneshot::channel();
    state
        .observation
        .configuration
        .enqueue(Work::Validate { request, response })?;
    Ok(Json(result.await.map_err(|_| unavailable())??).into_response())
}
