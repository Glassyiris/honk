//! Export, import and the revision list of the configuration db.

use axum::http::{HeaderValue, header};
use honk_config::parser::source_edit::{inline_sources, strip_listener_secrets};

use super::*;
use crate::native_api::store::db::MAX_REVISIONS;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    replace: bool,
}

impl ConfigService {
    pub(crate) fn store_kind(&self) -> StoreKind {
        self.store
            .read()
            .as_ref()
            .map_or(StoreKind::File, |store| store.kind())
    }

    fn database(&self) -> Option<Arc<dyn SourceStore>> {
        self.store
            .read()
            .clone()
            .filter(|store| store.kind() == StoreKind::Database)
    }

    /// True when the running configuration may differ from the recorded `head`.
    pub(crate) fn store_blocked(&self) -> bool {
        self.store
            .read()
            .as_ref()
            .is_some_and(|store| store.blocked())
    }

    /// `store` of `GET /config`; reads only cached state.
    pub(crate) fn store_value(&self) -> Value {
        let Some(store) = self.database() else {
            return json!({"kind":"file","revision":null,"parent":null,"recorded":true});
        };
        let recording = self.recording.read();
        let recorded = !store.blocked()
            && match &*recording {
                RecordState::Idle => true,
                RecordState::Pending(previous) => self
                    .sources
                    .accepted
                    .read()
                    .as_ref()
                    .is_some_and(|accepted| previous.as_ref() == Some(&accepted.revision)),
            };
        let head = store.database().and_then(|database| database.cached_head());
        json!({"kind":"db","revision":head.map(|(number,_)|number),"parent":head.and_then(|(_,parent)|parent),"recorded":recorded})
    }

    /// `writable` as advertised: false while a failed record blocks writes.
    pub(crate) fn editable(&self) -> bool {
        self.writable() && !self.store_blocked()
    }

    pub(crate) fn import_capability(&self) -> Value {
        json!({"available":self.database().is_some() && self.editable(),"replace_required":true})
    }

    pub(crate) fn revisions_capability(&self) -> Value {
        // Activating `head` stays possible while blocked: it is the way back in sync.
        json!({"available":self.database().is_some(),"can_activate":self.database().is_some() && self.writable(),"max_revisions":MAX_REVISIONS})
    }
}

pub(in crate::native_api) async fn export(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let config = state.config.read().await;
    let service = &state.observation.configuration;
    let accepted = service.sources.accepted.read().clone().ok_or_else(|| {
        error(
            StatusCode::NOT_FOUND,
            ErrorCode::CapabilityNotSupported,
            "Configuration sources are unavailable",
            id,
        )
    })?;
    let mut omitted = service.store_kind() == StoreKind::Database
        && !(config.experimental.native_api.secret.is_empty()
            && config.experimental.clash_api.secret.is_empty());
    let mut sources = accepted.update.sources.clone();
    for source in &mut sources {
        let stripped = strip_listener_secrets(&source.content).map_err(|_| unavailable())?;
        omitted |= stripped != source.content.as_ref();
        source.content = Arc::from(stripped);
    }
    let inlined = inline_sources(&sources).map_err(|_| unavailable())?;
    let (inlined, _) = ListenerSecrets::from_config(&config)
        .with_clash(&state.clash_secret)
        .mask(&inlined);
    let body = if omitted {
        format!("# listener secrets omitted\n{inlined}")
    } else {
        inlined
    };
    let store = service.store_value();
    let filename = match store["revision"].as_i64() {
        Some(revision) if store["recorded"] == true => format!("honk-r{revision}.dae"),
        _ => "honk.dae".to_owned(),
    };
    let etag = format!("\"{}\"", crate::configuration::digest(body.as_bytes()));
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|_| unavailable())?,
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(|_| unavailable())?,
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub(in crate::native_api) async fn revisions(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let service = &state.observation.configuration;
    let store = service.database().ok_or_else(unsupported)?;
    let store_error = || unavailable().with_details(json!({"stage":"store"}));
    let (active, rows) =
        tokio::task::spawn_blocking(move || store.database().map(|database| database.revisions()))
            .await
            .map_err(|_| store_error())?
            .ok_or_else(unsupported)?
            .map_err(|_| store_error())?;
    let secrets = service.secrets(service.sources.accepted.read().as_ref());
    let revisions: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let created_at = std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(u64::try_from(row.created_at).unwrap_or(0));
            json!({
                "revision":row.number, "parent":row.parent, "created_at":timestamp(created_at),
                "principal":row.principal, "origin":row.origin, "content_sha256":row.content_sha256,
                "bytes":row.bytes,
                "sources":row.sources.iter().map(|(path,sha256)|json!({"path":secrets.mask(path).0,"sha256":sha256})).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(
        Json(json!({"active":active,"max_revisions":MAX_REVISIONS,"revisions":revisions}))
            .into_response(),
    )
}

pub(in crate::native_api) async fn import(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let service = &state.observation.configuration;
    let store = service.database().ok_or_else(unsupported)?;
    if !service.writable() {
        return Err(denied());
    }
    json_type(&request)?;
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    let key = key.ok_or_else(precondition_required)?;
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    let body: Import = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let initialized = store
        .database()
        .and_then(|database| database.cached_head())
        .is_some();
    if initialized && !body.replace {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::StateConflict,
            "The configuration db already holds a revision; send replace to overwrite it",
            None,
        ));
    }
    let reservation = service.operations.reserve(
        state.principal(),
        "POST",
        "/api/v1/config/import",
        Some(&key),
        &bytes,
        crate::native_api::operations::OperationKind::Reload,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        service.enqueue(Work::Import { reservation })?;
    }
    Ok(admission.await?.into_response())
}

pub(in crate::native_api) async fn activate(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let service = &state.observation.configuration;
    let store = service.database().ok_or_else(unsupported)?;
    if !service.writable() {
        return Err(denied());
    }
    let path = request.uri().path().to_owned();
    let number = path
        .strip_suffix("/activate")
        .and_then(|rest| rest.rsplit('/').next())
        .and_then(|number| number.parse::<i64>().ok())
        .ok_or_else(not_found)?;
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    if request.body().size_hint().upper() != Some(0) {
        json_type(&request)?;
    }
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    if !bytes.is_empty()
        && !serde_json::from_slice::<Value>(&bytes)
            .ok()
            .is_some_and(|body| body.as_object().is_some_and(|object| object.is_empty()))
    {
        return Err(invalid());
    }
    let exists = tokio::task::spawn_blocking(move || {
        store
            .database()
            .map(|database| database.revision_exists(number))
    })
    .await
    .map_err(|_| unavailable())?;
    match exists {
        Some(Ok(true)) => {}
        Some(Ok(false)) => return Err(not_found()),
        None => return Err(unsupported()),
        Some(Err(_)) => return Err(unavailable().with_details(json!({"stage":"store"}))),
    }
    let reservation = service.operations.reserve(
        state.principal(),
        "POST",
        &path,
        key.as_deref(),
        &bytes,
        crate::native_api::operations::OperationKind::Reload,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        service.enqueue(Work::ActivateRevision {
            number,
            reservation,
        })?;
    }
    Ok(admission.await?.into_response())
}

fn precondition_required() -> ApiError {
    ApiError::new(
        StatusCode::PRECONDITION_REQUIRED,
        ErrorCode::PreconditionRequired,
        "Idempotency-Key is required",
        None,
    )
}
