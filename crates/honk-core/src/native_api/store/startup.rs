//! `--store db` startup: run the active revision, or import `-c` as revision 1.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, anyhow, ensure};
use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::parser::SourceSnapshot;
use honk_config::parser::source_edit::strip_listener_secrets;

use super::super::config::ListenerSecrets as MaskSet;
use super::db::{DbStore, ListenerSecrets, StoreError};
use crate::configuration::{SourceUpdate, limits};

pub(crate) struct DatabaseStartup {
    pub(crate) store: Arc<DbStore>,
    pub(crate) config: Config,
    pub(crate) sources: SourceUpdate,
    import: Option<Import>,
    /// The revision `config` was loaded from.
    head: Option<i64>,
}

struct Import {
    stripped: Vec<SourceSnapshot>,
    forbidden: MaskSet,
    secrets: ListenerSecrets,
}

/// The tree with every listener `secret:` removed, keyed by path, and every
/// secret value it held. Refused when a value survives, for example in a
/// comment or a file name, because the db would keep it.
pub(crate) fn strip_tree(
    originals: &[SourceSnapshot],
) -> Result<(HashMap<PathBuf, Arc<str>>, MaskSet), PathBuf> {
    let forbidden = MaskSet::new(originals, "");
    let mut overlay = HashMap::new();
    for source in originals {
        let stripped = strip_listener_secrets(&source.content)
            .ok()
            .filter(|stripped| {
                !forbidden.contains(stripped) && !forbidden.contains(&source.path.to_string_lossy())
            })
            .ok_or_else(|| source.path.clone())?;
        overlay.insert(source.path.clone(), Arc::<str>::from(stripped));
    }
    Ok((overlay, forbidden))
}

impl DatabaseStartup {
    /// `entry` must be absolute and lexically normal; it is read only while the db is empty.
    pub(crate) fn open(
        entry: &Path,
        data_dir: &Path,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> anyhow::Result<Self> {
        let store = Arc::new(DbStore::open(data_dir, entry).map_err(store_error)?);
        if let Some((head, _)) = store.cached_head() {
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
                head: Some(head),
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
        let (overlay, forbidden) = strip_tree(&originals).map_err(|path| {
            anyhow!(
                "listener secrets in {} cannot be stripped completely; remove copies of secret values",
                path.display()
            )
        })?;
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
                forbidden,
                secrets,
            }),
            head: None,
        })
    }

    /// Call with the instance lock held: records the imported tree as revision 1,
    /// or refuses when another instance moved `head` after it was loaded.
    pub(crate) fn record(&mut self) -> anyhow::Result<()> {
        let Some(import) = self.import.take() else {
            let current = self.store.head().map_err(store_error)?;
            ensure!(
                current == self.head,
                "configuration db head moved from {:?} to {:?} during startup; start again",
                self.head,
                current
            );
            return Ok(());
        };
        self.store
            .initialize(
                &import.stripped,
                &import.forbidden,
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
