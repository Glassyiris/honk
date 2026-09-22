//! Where the coordinator reads and writes the `.dae` sources it administers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::error::DetailedConfigError;
use honk_config::parser::LoadedConfig;

use super::ApiError;
use super::config_write::{SourceFile, WriteError};
use crate::configuration::{MAX_SOURCE_BYTES, limits};

/// Revision fence taken before a candidate is validated and checked again on commit.
pub(crate) enum Pin {
    File(SourceFile),
}

impl Pin {
    pub(crate) fn sha256(&self) -> String {
        match self {
            Self::File(file) => file.sha256(),
        }
    }
}

/// Blocking source access; callers run it inside `spawn_blocking`.
pub(crate) trait SourceStore: Send + Sync + 'static {
    fn entry(&self) -> &Path;
    /// Extra authorisation root for dependencies: the entry directory in file mode.
    fn dependency_root(&self) -> Option<&Path>;
    /// Map a client source label to the path the loader knows it by.
    fn resolve(&self, label: &str) -> Result<PathBuf, ApiError>;
    fn load(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<LoadedConfig, DetailedConfigError>;
    fn pin(&self, path: &Path) -> Result<Pin, WriteError>;
    /// `before` runs after the last precondition and must recheck the candidate.
    fn commit(
        &self,
        pin: Pin,
        content: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<(), WriteError>;
}

/// Sources read from and replaced in the operator's `-c` tree.
pub(crate) struct FileStore {
    entry: PathBuf,
}

impl FileStore {
    pub(crate) fn new(entry: PathBuf) -> Self {
        Self { entry }
    }
}

impl SourceStore for FileStore {
    fn entry(&self) -> &Path {
        &self.entry
    }

    fn dependency_root(&self) -> Option<&Path> {
        self.entry.parent()
    }

    fn resolve(&self, label: &str) -> Result<PathBuf, ApiError> {
        let root = self.entry.parent().ok_or_else(super::config::invalid)?;
        super::config::resolve_source_path(root, label)
    }

    fn load(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<LoadedConfig, DetailedConfigError> {
        Config::from_dae_file_with_sources(&self.entry, overlay, limits(), diagnostics)
    }

    fn pin(&self, path: &Path) -> Result<Pin, WriteError> {
        SourceFile::open(path, MAX_SOURCE_BYTES).map(Pin::File)
    }

    fn commit(
        &self,
        pin: Pin,
        content: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<(), WriteError> {
        match pin {
            Pin::File(file) => {
                let expected = file.sha256();
                file.replace(&expected, content, before)
            }
        }
    }
}
