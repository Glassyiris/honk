//! `--store db` startup: run the active revision, or import `-c` as revision 1.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, anyhow, ensure};
use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::parser::SourceSnapshot;
use honk_config::parser::source_edit::strip_listener_secrets;

use super::db::{DbStore, ListenerSecrets, StoreError};
use crate::configuration::{SourceUpdate, limits};

pub(crate) struct DatabaseStartup {
    pub(crate) store: Arc<DbStore>,
    pub(crate) config: Config,
    pub(crate) sources: SourceUpdate,
    import: Option<Import>,
}

struct Import {
    stripped: Vec<SourceSnapshot>,
    originals: Vec<SourceSnapshot>,
    secrets: ListenerSecrets,
}

impl DatabaseStartup {
    /// `entry` must be absolute and lexically normal; it is read only while the db is empty.
    pub(crate) fn open(
        entry: &Path,
        data_dir: &Path,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> anyhow::Result<Self> {
        let store = Arc::new(DbStore::open(data_dir, entry).map_err(store_error)?);
        if store.head().map_err(store_error)?.is_some() {
            let loaded = store.load(&HashMap::new(), diagnostics)?;
            let config = crate::admit_operator_config(
                loaded.config,
                loaded.sources[0].source.clone(),
                diagnostics,
            )?;
            same_data_dir(&config, data_dir)?;
            return Ok(Self {
                store,
                config,
                sources: update(loaded.sources),
                import: None,
            });
        }
        let (config, sources) = crate::load_operator_config_captured(store.entry(), diagnostics)
            .with_context(|| {
                format!(
                    "the configuration db is empty and {} cannot be imported",
                    entry.display()
                )
            })?;
        let originals = sources
            .ok_or_else(|| anyhow!("--store db imports a dae source tree"))?
            .sources;
        let native = &config.experimental.native_api;
        ensure!(
            native.enabled && native.config_write && native.credentialed(),
            "--store db needs experimental.native_api with enabled, config_write and a credential"
        );
        same_data_dir(&config, data_dir)?;
        let mut overlay = HashMap::new();
        for source in &originals {
            let stripped = strip_listener_secrets(&source.content).map_err(|_| {
                anyhow!(
                    "listener secrets in {} cannot be stripped",
                    source.path.display()
                )
            })?;
            overlay.insert(source.path.clone(), Arc::<str>::from(stripped));
        }
        let mut loaded =
            Config::from_dae_sources_in_memory(store.entry(), &overlay, limits(), &mut Vec::new())?;
        let secrets = ListenerSecrets {
            native_api: config.experimental.native_api.secret.clone(),
            clash_api: config.experimental.clash_api.secret.clone(),
        };
        loaded.config.experimental.native_api.secret = secrets.native_api.clone();
        loaded.config.experimental.clash_api.secret = secrets.clash_api.clone();
        ensure!(
            loaded.config == config
                && loaded.sources.len() == originals.len()
                && loaded
                    .sources
                    .iter()
                    .zip(&originals)
                    .all(|(stripped, original)| stripped.path == original.path),
            "{} does not read back the same once listener secrets are stripped",
            entry.display()
        );
        Ok(Self {
            store,
            config,
            sources: update(loaded.sources.clone()),
            import: Some(Import {
                stripped: loaded.sources,
                originals,
                secrets,
            }),
        })
    }

    /// Records the imported tree as revision 1; call it with the instance lock held.
    pub(crate) fn record(&mut self) -> anyhow::Result<()> {
        let Some(import) = self.import.take() else {
            return Ok(());
        };
        self.store
            .initialize(
                &import.stripped,
                &import.originals,
                &import.secrets,
                "startup",
            )
            .map_err(store_error)?;
        Ok(())
    }
}

fn update(sources: Vec<SourceSnapshot>) -> SourceUpdate {
    SourceUpdate {
        sources,
        dependencies: Vec::new(),
        geo_sources: None,
    }
}

fn same_data_dir(config: &Config, data_dir: &Path) -> anyhow::Result<()> {
    ensure!(
        Path::new(&config.global.data_dir) == data_dir,
        "global.data_dir {} differs from --data-dir {}",
        config.global.data_dir,
        data_dir.display()
    );
    Ok(())
}

fn store_error(error: StoreError) -> anyhow::Error {
    anyhow!("configuration db: {error}")
}

#[cfg(test)]
mod tests;
