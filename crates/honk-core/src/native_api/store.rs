//! Where the coordinator reads and writes the `.dae` sources it administers.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use honk_config::Config;
use honk_config::diagnostic::DetailedDiagnostic;
use honk_config::error::DetailedConfigError;
use honk_config::parser::{LoadedConfig, SourceSnapshot};

use super::ApiError;
use super::config_write::{CreatedFile, SourceFile, WriteError};
use crate::configuration::{MAX_SOURCE_BYTES, limits};

pub(crate) mod db;
pub(crate) mod startup;

pub(crate) use db::DbStore;
pub(crate) use startup::DatabaseStartup;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreKind {
    File,
    Database,
}

/// Revision fence taken before a candidate is validated and checked again on commit.
#[allow(clippy::large_enum_variant)] // one per source for a single write
pub(crate) enum Pin {
    File(SourceFile),
    Revision(db::RevisionPin),
}

impl Pin {
    pub(crate) fn sha256(&self) -> String {
        match self {
            Self::File(file) => file.sha256(),
            Self::Revision(pin) => pin.sha256.clone(),
        }
    }

    /// The pinned file, for alias checks against other open files.
    pub(crate) fn file(&self) -> Option<&SourceFile> {
        match self {
            Self::File(file) => Some(file),
            Self::Revision(_) => None,
        }
    }
}

/// What `commit` left for `promote` once the candidate is active.
pub(crate) enum Committed {
    Written,
    /// A new file on disk; a failed activation removes it again.
    Created(CreatedFile),
    Pending(db::Pending),
    /// `head` itself re-activated to bring a blocked store back in sync; records nothing.
    Resync,
}

impl Committed {
    pub(crate) fn written(&self) -> bool {
        matches!(self, Self::Written | Self::Created(_))
    }
}

/// Blocking source access; callers run it inside `spawn_blocking`.
pub(crate) trait SourceStore: Send + Sync + 'static {
    fn kind(&self) -> StoreKind;
    fn entry(&self) -> &Path;
    /// Extra authorisation root for dependencies: the entry directory in file mode,
    /// `None` in db mode.
    fn dependency_root(&self) -> Option<&Path>;
    /// Map a client source label to the path the loader knows it by.
    fn resolve(&self, label: &str) -> Result<PathBuf, ApiError>;
    fn load(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<LoadedConfig, DetailedConfigError>;
    fn pin(&self, path: &Path) -> Result<Pin, WriteError>;
    fn recheck(&self, pin: &Pin) -> Result<(), WriteError>;
    /// `before` runs after the last precondition and must recheck the candidate.
    fn commit(
        &self,
        pin: Pin,
        content: &str,
        candidate: &[SourceSnapshot],
        principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Committed, WriteError>;
    /// Adds `path` holding `content`, never replacing a source already there.
    /// `before` runs after the last precondition and must recheck the candidate.
    fn create(
        &self,
        path: &Path,
        content: &str,
        candidate: &[SourceSnapshot],
        principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Committed, WriteError>;
    /// Records an activated candidate. A failure blocks later writes until restart.
    fn promote(&self, committed: Committed) -> Result<(), WriteError>;
    /// Refuses later writes until restart: the running config may differ from the store.
    fn block(&self);
    fn database(&self) -> Option<&DbStore> {
        None
    }
    /// True after a failed record: the daemon may run what the store does not hold.
    fn blocked(&self) -> bool {
        false
    }
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
    fn kind(&self) -> StoreKind {
        StoreKind::File
    }

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

    fn recheck(&self, pin: &Pin) -> Result<(), WriteError> {
        pin.file().ok_or(WriteError::Conflict)?.recheck()
    }

    fn commit(
        &self,
        pin: Pin,
        content: &str,
        _candidate: &[SourceSnapshot],
        _principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Committed, WriteError> {
        let Pin::File(file) = pin else {
            return Err(WriteError::Conflict);
        };
        let expected = file.sha256();
        file.replace(&expected, content, before)?;
        Ok(Committed::Written)
    }

    fn create(
        &self,
        path: &Path,
        content: &str,
        _candidate: &[SourceSnapshot],
        _principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Committed, WriteError> {
        let mode = std::fs::metadata(&self.entry)
            .map_err(|_| WriteError::Unavailable)?
            .mode();
        super::config_write::create_new(path, content.as_bytes(), mode, before)
            .map(Committed::Created)
    }

    fn promote(&self, _committed: Committed) -> Result<(), WriteError> {
        Ok(())
    }

    fn block(&self) {}
}

impl SourceStore for DbStore {
    fn kind(&self) -> StoreKind {
        StoreKind::Database
    }

    fn entry(&self) -> &Path {
        DbStore::entry(self)
    }

    fn dependency_root(&self) -> Option<&Path> {
        None
    }

    fn resolve(&self, label: &str) -> Result<PathBuf, ApiError> {
        DbStore::resolve(self, label)
    }

    fn load(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<LoadedConfig, DetailedConfigError> {
        DbStore::load(self, overlay, diagnostics)
    }

    fn pin(&self, path: &Path) -> Result<Pin, WriteError> {
        DbStore::pin(self, path).map(Pin::Revision)
    }

    fn recheck(&self, pin: &Pin) -> Result<(), WriteError> {
        match pin {
            Pin::Revision(pin) => DbStore::recheck(self, pin),
            Pin::File(_) => Err(WriteError::Conflict),
        }
    }

    fn commit(
        &self,
        pin: Pin,
        content: &str,
        candidate: &[SourceSnapshot],
        principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Committed, WriteError> {
        let Pin::Revision(pin) = pin else {
            return Err(WriteError::Conflict);
        };
        DbStore::commit(self, pin, content, candidate, principal, before).map(Committed::Pending)
    }

    fn create(
        &self,
        path: &Path,
        content: &str,
        candidate: &[SourceSnapshot],
        principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Committed, WriteError> {
        // The entry's pin fences `head`; commit then checks the new path's content.
        let pin = db::RevisionPin {
            path: path.to_owned(),
            ..DbStore::pin(self, DbStore::entry(self))?
        };
        DbStore::commit(self, pin, content, candidate, principal, before).map(Committed::Pending)
    }

    fn promote(&self, committed: Committed) -> Result<(), WriteError> {
        match committed {
            Committed::Pending(pending) => DbStore::promote(self, pending).map(drop),
            Committed::Resync => {
                self.unblock();
                Ok(())
            }
            Committed::Written | Committed::Created(_) => Ok(()),
        }
    }

    fn block(&self) {
        DbStore::block(self);
    }

    fn database(&self) -> Option<&DbStore> {
        Some(self)
    }

    fn blocked(&self) -> bool {
        DbStore::blocked(self)
    }
}
