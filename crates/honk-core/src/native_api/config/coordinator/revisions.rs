//! `import` and revision activation: whole-tree candidates recorded as new revisions.

use super::*;
use crate::native_api::store::db::Origin;
use crate::native_api::store::startup::strip_tree;

impl Worker {
    /// Reads the `-c` tree, strips its listener secrets and validates it as the next revision.
    pub(super) async fn prepare_import(&self, principal: &str) -> Result<Prepared, ApiError> {
        let store = self.store.clone().ok_or_else(unsupported)?;
        self.prepare_tree(
            principal,
            Some(Origin::Import),
            move |store, diagnostics| {
                let database = store.database().ok_or_else(unsupported)?;
                let entry = database.import_entry();
                if entry != store.entry() {
                    return Err(denied());
                }
                let originals = Config::from_dae_file_with_sources(
                    entry,
                    &HashMap::new(),
                    limits(),
                    diagnostics,
                )
                .map_err(|error| config_error(error, diagnostics, &[], None, None))?;
                let (overlay, _) =
                    strip_tree(&originals.sources).map_err(|_| management::unsupported_value())?;
                let mut loaded =
                    Config::from_dae_sources_in_memory(entry, &overlay, limits(), &mut Vec::new())
                        .map_err(|error| config_error(error, diagnostics, &[], None, None))?;
                let original = &originals.config.experimental;
                loaded.config.experimental.native_api.secret = original.native_api.secret.clone();
                loaded.config.experimental.clash_api.secret = original.clash_api.secret.clone();
                if loaded.config != originals.config {
                    return Err(management::unsupported_value());
                }
                Ok(loaded)
            },
            store,
        )
        .await
    }

    /// Validates stored revision `number` as the next revision. `resync` re-activates
    /// `head` itself for a blocked store and records nothing.
    pub(super) async fn prepare_revision(
        &self,
        number: i64,
        principal: &str,
        resync: bool,
    ) -> Result<Prepared, ApiError> {
        let store = self.store.clone().ok_or_else(unsupported)?;
        self.prepare_tree(
            principal,
            (!resync).then_some(Origin::Activate),
            move |store, diagnostics| {
                let database = store.database().ok_or_else(unsupported)?;
                database
                    .load_revision(number, diagnostics)
                    .map_err(|_| unavailable().with_details(json!({"stage":"store"})))?
                    .ok_or_else(not_found)
            },
            store,
        )
        .await
    }

    async fn prepare_tree(
        &self,
        principal: &str,
        origin: Option<Origin>,
        read: impl FnOnce(
            &dyn SourceStore,
            &mut Vec<DetailedDiagnostic>,
        ) -> Result<LoadedConfig, ApiError>
        + Send
        + 'static,
        store: Arc<dyn SourceStore>,
    ) -> Result<Prepared, ApiError> {
        let active = self.active.read().await.clone();
        let data_dir = self.data_dir.clone();
        let deferred = self
            .subscriptions
            .deferred_subscriptions()
            .await
            .map_err(|_| unavailable())?;
        let principal = principal.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut diagnostics = Vec::new();
            let loaded = read(&*store, &mut diagnostics)?;
            let parsed_sources = loaded.sources.clone();
            let validated = offline::validate_for_coordinator(
                loaded,
                store.dependency_root(),
                &active,
                &data_dir,
                limits(),
                &mut diagnostics,
                &deferred,
                None,
                &[],
            )
            .map_err(|error| config_error(error, &diagnostics, &parsed_sources, None, None))?;
            if diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity == Severity::Error)
            {
                return Err(diagnostics_error(
                    &diagnostics,
                    &validated.sources,
                    None,
                    None,
                ));
            }
            if validated.config.experimental.native_api != active.experimental.native_api
                || validated.config.experimental.clash_api.secret
                    != active.experimental.clash_api.secret
                || validated.config.global.data_dir != active.global.data_dir
            {
                return Err(denied());
            }
            let database = store.database().ok_or_else(unsupported)?;
            let committed = match origin {
                Some(origin) => Committed::Pending(
                    database
                        .stage(&validated.sources, &principal, origin)
                        .map_err(|error| store_write_error(StoreKind::Database, error))?,
                ),
                None => Committed::Resync,
            };
            let update = SourceUpdate {
                sources: validated.sources,
                dependencies: validated.dependencies,
                geo_sources: None,
            };
            Ok((validated.config, update, diagnostics, committed))
        })
        .await
        .map_err(|_| unavailable())?
    }
}
