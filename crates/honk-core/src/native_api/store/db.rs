//! Configuration revisions in `<data_dir>/native-api/config.db`.
//!
//! A write is activated first and recorded after: `commit` only fences `head`,
//! and `promote` inserts the revision and moves `head` in one transaction, so a
//! crash in between restarts from the old `head` that the client never saw replaced.

use std::collections::HashMap;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use honk_config::Config;
use honk_config::diagnostic::{DetailedDiagnostic, DiagnosticSources, SettingPath};
use honk_config::error::{DetailedConfigError, ErrorCategory};
use honk_config::parser::source_edit::{inline_sources, restore_listener_secrets};
use honk_config::parser::{LoadedConfig, SourceSnapshot};
use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::{Mode, mkdirat};
use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::super::ApiError;
use super::super::auth::{CREDENTIAL_DIR, DIR_FLAGS, effective_uid};
use super::super::config::ListenerSecrets as MaskSet;
use super::super::config_write::WriteError;
use crate::configuration::{MAX_SOURCE_BYTES, MAX_SOURCES, digest, limits};

const DB_FILE: &str = "config.db";
const APPLICATION_ID: i64 = 0x686f_6e6b;
const SCHEMA_VERSION: i64 = 1;
pub(crate) const MAX_REVISIONS: usize = 50;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 4096;

const SCHEMA: &str = "
CREATE TABLE revision (
  number INTEGER PRIMARY KEY AUTOINCREMENT,
  parent INTEGER REFERENCES revision(number) ON DELETE SET NULL,
  created_at INTEGER NOT NULL, principal TEXT NOT NULL,
  origin TEXT NOT NULL CHECK (origin IN ('import','write','activate')),
  root TEXT NOT NULL,
  sources TEXT NOT NULL,
  content_sha256 TEXT NOT NULL, bytes INTEGER NOT NULL);
CREATE TABLE head (id INTEGER PRIMARY KEY CHECK (id=1), active INTEGER NOT NULL REFERENCES revision(number));
CREATE TABLE listener_secret (api TEXT PRIMARY KEY CHECK (api IN ('native_api','clash_api')), value TEXT NOT NULL);
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("configuration database is unavailable")]
    Unavailable,
    #[error("configuration database path is unsafe")]
    Unsafe,
    #[error("configuration database is corrupt")]
    Corrupt,
    #[error("configuration database has a foreign application id or a newer schema")]
    Unsupported,
    #[error("configuration database already holds a revision")]
    NotEmpty,
    #[error("configuration revision is invalid")]
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    Import,
    Write,
    Activate,
}

impl Origin {
    fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Write => "write",
            Self::Activate => "activate",
        }
    }
}

/// One row of the revision list; content stays in the db.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RevisionInfo {
    pub(crate) number: i64,
    pub(crate) parent: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) principal: String,
    pub(crate) origin: String,
    pub(crate) content_sha256: String,
    pub(crate) bytes: i64,
    /// `(name, sha256)` in loader preorder.
    pub(crate) sources: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ListenerSecrets {
    pub(crate) native_api: String,
    pub(crate) clash_api: String,
}

/// Head fence for one source of the active revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RevisionPin {
    pub(crate) number: i64,
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

/// An activated candidate that `promote` still has to record.
pub(crate) struct Pending {
    parent: i64,
    sources: Vec<StoredSource>,
    principal: String,
    origin: Origin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSource {
    name: String,
    parent: Option<usize>,
    content: String,
    sha256: String,
}

struct Revision {
    sources: Vec<StoredSource>,
}

pub(crate) struct DbStore {
    // Held so the checked directory stays the one SQLite resolved.
    _directory: File,
    connection: Mutex<Connection>,
    entry: PathBuf,
    root: PathBuf,
    /// The `-c` entry this process started with; `import` reads it.
    import_entry: PathBuf,
    /// Set when the daemon may run something `head` does not record; cleared by
    /// restart or by re-activating `head`.
    blocked: AtomicBool,
    /// `(head, parent)` as last read or written, so readers need no SQLite call.
    head: Mutex<Option<(i64, Option<i64>)>>,
    secrets: Mutex<ListenerSecrets>,
    #[cfg(test)]
    pub(crate) fail_promote: AtomicBool,
}

impl DbStore {
    /// Opens or creates the db. `entry` names the main source when the db is still
    /// empty; otherwise the active revision's own entry wins.
    pub(crate) fn open(data_dir: &Path, entry: &Path) -> Result<Self, StoreError> {
        let (directory, mut connection) = connect(data_dir, true)?;
        prepare(&mut connection)?;
        let import_entry = lexical(entry)?;
        let root_entry = match active_revision(&connection)? {
            Some((_, root, revision)) => root.join(&revision.sources[0].name),
            None => import_entry.clone(),
        };
        let root = root_entry
            .parent()
            .ok_or(StoreError::Invalid)?
            .to_path_buf();
        let head = head_and_parent(&connection)?;
        let secrets = listener_secrets(&connection)?;
        Ok(Self {
            _directory: directory,
            connection: Mutex::new(connection),
            entry: root_entry,
            root,
            import_entry,
            blocked: AtomicBool::new(false),
            head: Mutex::new(head),
            secrets: Mutex::new(secrets),
            #[cfg(test)]
            fail_promote: AtomicBool::new(false),
        })
    }

    /// The cached `(head, parent)`; never touches SQLite.
    pub(crate) fn cached_head(&self) -> Option<(i64, Option<i64>)> {
        *self.head.lock()
    }

    pub(crate) fn listener_secrets(&self) -> ListenerSecrets {
        self.secrets.lock().clone()
    }

    pub(crate) fn blocked(&self) -> bool {
        self.blocked.load(Ordering::Acquire)
    }

    /// The daemon runs `head` again after a re-activation.
    pub(crate) fn unblock(&self) {
        self.blocked.store(false, Ordering::Release);
    }

    pub(crate) fn revision_exists(&self, number: i64) -> Result<bool, StoreError> {
        self.connection
            .lock()
            .query_row("SELECT 1 FROM revision WHERE number = ?1", [number], |_| {
                Ok(())
            })
            .optional()
            .map(|row| row.is_some())
            .map_err(sql)
    }

    pub(crate) fn entry(&self) -> &Path {
        &self.entry
    }

    pub(crate) fn head(&self) -> Result<Option<i64>, StoreError> {
        head(&self.connection.lock())
    }

    pub(crate) fn import_entry(&self) -> &Path {
        &self.import_entry
    }

    /// Newest first.
    pub(crate) fn revisions(&self) -> Result<Vec<RevisionInfo>, StoreError> {
        let connection = self.connection.lock();
        let mut statement = connection
            .prepare(
                "SELECT number, parent, created_at, principal, origin, content_sha256, bytes, sources
                 FROM revision ORDER BY number DESC",
            )
            .map_err(sql)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    RevisionInfo {
                        number: row.get(0)?,
                        parent: row.get(1)?,
                        created_at: row.get(2)?,
                        principal: row.get(3)?,
                        origin: row.get(4)?,
                        content_sha256: row.get(5)?,
                        bytes: row.get(6)?,
                        sources: Vec::new(),
                    },
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(sql)?;
        let mut revisions = Vec::new();
        for row in rows {
            let (mut info, sources) = row.map_err(sql)?;
            if digest(sources.as_bytes()) != info.content_sha256 {
                return Err(StoreError::Corrupt);
            }
            let sources: Vec<StoredSource> =
                serde_json::from_str(&sources).map_err(|_| StoreError::Corrupt)?;
            info.sources = sources
                .into_iter()
                .map(|source| (source.name, source.sha256))
                .collect();
            revisions.push(info);
        }
        Ok(revisions)
    }

    /// Loads revision `number` as the loader sees it, secrets re-applied.
    pub(crate) fn load_revision(
        &self,
        number: i64,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Option<LoadedConfig>, StoreError> {
        let (revision, secrets) = {
            let connection = self.connection.lock();
            let Some((root, revision)) = revision(&connection, number)? else {
                return Ok(None);
            };
            if root != self.root {
                return Err(StoreError::Invalid);
            }
            (revision, self.secrets.lock().clone())
        };
        let sources = revision
            .sources
            .into_iter()
            .map(|source| (self.root.join(source.name), Arc::from(source.content)))
            .collect();
        self.load_sources(&sources, &secrets, diagnostics)
            .map(Some)
            .map_err(|_| StoreError::Invalid)
    }

    /// A candidate that did not come from editing one pinned source.
    pub(crate) fn stage(
        &self,
        candidate: &[SourceSnapshot],
        principal: &str,
        origin: Origin,
    ) -> Result<Pending, WriteError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(WriteError::Unavailable);
        }
        let parent = self
            .head()
            .map_err(|_| WriteError::Unavailable)?
            .ok_or(WriteError::Unavailable)?;
        let sources = self.stored_now(candidate)?;
        Ok(Pending {
            parent,
            sources,
            principal: principal.to_owned(),
            origin,
        })
    }

    fn load_sources(
        &self,
        sources: &HashMap<PathBuf, Arc<str>>,
        secrets: &ListenerSecrets,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<LoadedConfig, DetailedConfigError> {
        let mut loaded =
            Config::from_dae_sources_in_memory(&self.entry, sources, limits(), diagnostics)?;
        loaded.config.experimental.native_api.secret = secrets.native_api.clone();
        loaded.config.experimental.clash_api.secret = secrets.clash_api.clone();
        Ok(loaded)
    }

    /// Records the first revision; refused once any revision exists.
    /// `forbidden` holds every listener secret value the operator's tree carried.
    pub(crate) fn initialize(
        &self,
        sources: &[SourceSnapshot],
        forbidden: &MaskSet,
        secrets: &ListenerSecrets,
        principal: &str,
    ) -> Result<i64, StoreError> {
        let stored = self.stored(sources, &forbidden.clone().with_all(secrets))?;
        let mut connection = self.connection.lock();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if head(&transaction)?.is_some() {
            return Err(StoreError::NotEmpty);
        }
        let number = insert(
            &transaction,
            None,
            &self.root,
            &stored,
            principal,
            Origin::Import,
        )?;
        for (api, value) in [
            ("native_api", &secrets.native_api),
            ("clash_api", &secrets.clash_api),
        ] {
            if !value.is_empty() {
                transaction
                    .execute(
                        "INSERT INTO listener_secret (api, value) VALUES (?1, ?2)",
                        params![api, value],
                    )
                    .map_err(sql)?;
            }
        }
        transaction
            .execute("INSERT INTO head (id, active) VALUES (1, ?1)", [number])
            .map_err(sql)?;
        transaction.commit().map_err(sql)?;
        *self.head.lock() = Some((number, None));
        *self.secrets.lock() = secrets.clone();
        Ok(number)
    }

    /// Lexical: the db holds virtual paths, so nothing under `root` is opened.
    pub(crate) fn resolve(&self, label: &str) -> Result<PathBuf, ApiError> {
        let input = Path::new(label);
        let path = if input.is_absolute() {
            input
                .strip_prefix(&self.root)
                .map_err(|_| super::super::config::denied())?
        } else {
            input
        };
        let path: PathBuf = path.components().collect();
        valid_name(&path).map_err(|_| super::super::config::denied())?;
        Ok(self.root.join(path))
    }

    pub(crate) fn load(
        &self,
        overlay: &HashMap<PathBuf, Arc<str>>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<LoadedConfig, DetailedConfigError> {
        let revision = active_revision(&self.connection.lock())
            .ok()
            .flatten()
            .map(|(_, _, revision)| revision);
        let Some(revision) = revision else {
            return Err(store_unavailable());
        };
        let secrets = self.secrets.lock().clone();
        let mut sources: HashMap<PathBuf, Arc<str>> = revision
            .sources
            .into_iter()
            .map(|source| (self.root.join(source.name), Arc::from(source.content)))
            .collect();
        sources.extend(
            overlay
                .iter()
                .map(|(path, content)| (path.clone(), content.clone())),
        );
        self.load_sources(&sources, &secrets, diagnostics)
    }

    pub(crate) fn pin(&self, path: &Path) -> Result<RevisionPin, WriteError> {
        if self.blocked() {
            return Err(WriteError::Unavailable);
        }
        let connection = self.connection.lock();
        let (number, _, revision) = active_revision(&connection)
            .map_err(|_| WriteError::Unavailable)?
            .ok_or(WriteError::Unavailable)?;
        let source = revision
            .sources
            .iter()
            .find(|source| self.root.join(&source.name) == path)
            .ok_or(WriteError::Conflict)?;
        Ok(RevisionPin {
            number,
            path: path.to_path_buf(),
            sha256: source.sha256.clone(),
        })
    }

    pub(crate) fn recheck(&self, pin: &RevisionPin) -> Result<(), WriteError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(WriteError::Unavailable);
        }
        match head(&self.connection.lock()) {
            Ok(Some(number)) if number == pin.number => Ok(()),
            Ok(_) => Err(WriteError::Conflict),
            Err(_) => Err(WriteError::Unavailable),
        }
    }

    /// Fences `head` and runs `before`; nothing is written until `promote`.
    pub(crate) fn commit(
        &self,
        pin: RevisionPin,
        content: &str,
        candidate: &[SourceSnapshot],
        principal: &str,
        before: Box<dyn FnOnce() -> Result<(), WriteError> + '_>,
    ) -> Result<Pending, WriteError> {
        if !candidate
            .iter()
            .any(|source| source.path == pin.path && source.content.as_ref() == content)
        {
            return Err(WriteError::Conflict);
        }
        let sources = self.stored_now(candidate)?;
        self.recheck(&pin)?;
        before()?;
        self.recheck(&pin)?;
        Ok(Pending {
            parent: pin.number,
            sources,
            principal: principal.to_owned(),
            origin: Origin::Write,
        })
    }

    /// Records an activated candidate as the new `head`. Any failure blocks later
    /// writes, because the daemon now runs what `head` does not describe.
    pub(crate) fn promote(&self, pending: Pending) -> Result<i64, WriteError> {
        let result = self.promote_inner(&pending);
        if result.is_err() {
            self.block();
        }
        result
    }

    pub(crate) fn block(&self) {
        self.blocked.store(true, Ordering::Release);
    }

    fn promote_inner(&self, pending: &Pending) -> Result<i64, WriteError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(WriteError::Unavailable);
        }
        #[cfg(test)]
        if self.fail_promote.load(Ordering::Acquire) {
            return Err(WriteError::Unavailable);
        }
        let mut connection = self.connection.lock();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(write_sql)?;
        if head(&transaction).map_err(|_| WriteError::Unavailable)? != Some(pending.parent) {
            return Err(WriteError::Conflict);
        }
        let number = insert(
            &transaction,
            Some(pending.parent),
            &self.root,
            &pending.sources,
            &pending.principal,
            pending.origin,
        )
        .map_err(|_| WriteError::Unavailable)?;
        transaction
            .execute("UPDATE head SET active = ?1 WHERE id = 1", [number])
            .map_err(write_sql)?;
        prune(&transaction, number).map_err(write_sql)?;
        if let Err(error) = transaction.commit() {
            log_sql(&error);
            return match head(&connection) {
                Ok(Some(active)) if active == number => {
                    *self.head.lock() = Some((number, Some(pending.parent)));
                    Ok(number)
                }
                _ => Err(WriteError::Unavailable),
            };
        }
        *self.head.lock() = Some((number, Some(pending.parent)));
        Ok(number)
    }

    /// `stored` against the listener secrets this db already holds.
    fn stored_now(&self, candidate: &[SourceSnapshot]) -> Result<Vec<StoredSource>, WriteError> {
        let forbidden = MaskSet::new(&[], "").with_all(&self.secrets.lock());
        self.stored(candidate, &forbidden)
            .map_err(|error| match error {
                StoreError::Invalid => WriteError::UnsafePath,
                _ => WriteError::Unavailable,
            })
    }

    /// Refuses any source whose content or name still carries a `forbidden` value.
    fn stored(
        &self,
        sources: &[SourceSnapshot],
        forbidden: &MaskSet,
    ) -> Result<Vec<StoredSource>, StoreError> {
        let bytes: usize = sources.iter().map(|source| source.content.len()).sum();
        if sources.is_empty()
            || sources.len() > MAX_SOURCES
            || bytes > MAX_SOURCE_BYTES
            || sources[0].path != self.entry
        {
            return Err(StoreError::Invalid);
        }
        sources
            .iter()
            .map(|source| {
                if source.contains_api_secret
                    || forbidden.contains(&source.content)
                    || forbidden.contains(&source.path.to_string_lossy())
                {
                    return Err(StoreError::Invalid);
                }
                let name = source
                    .path
                    .strip_prefix(&self.root)
                    .map_err(|_| StoreError::Invalid)?;
                valid_name(name)?;
                Ok(StoredSource {
                    name: name.to_str().ok_or(StoreError::Invalid)?.to_owned(),
                    parent: source.parent,
                    content: source.content.to_string(),
                    sha256: digest(source.content.as_bytes()),
                })
            })
            .collect()
    }
}

/// Opens the checked directory and the SQLite file in it; `create` makes both
/// when missing, otherwise the db is opened read-only and must exist.
fn connect(data_dir: &Path, create: bool) -> Result<(File, Connection), StoreError> {
    let parent =
        File::from(open(data_dir, DIR_FLAGS, Mode::empty()).map_err(|_| StoreError::Unavailable)?);
    if create {
        match mkdirat(&parent, CREDENTIAL_DIR, Mode::S_IRWXU) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(_) => return Err(StoreError::Unavailable),
        }
    }
    let directory =
        File::from(openat(&parent, CREDENTIAL_DIR, DIR_FLAGS, Mode::empty()).map_err(path_error)?);
    private(&directory, true)?;
    let access = if create {
        OFlag::O_RDWR
    } else {
        OFlag::O_RDONLY
    };
    let existing = || {
        openat(
            &directory,
            DB_FILE,
            access | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(path_error)
    };
    let file = if create {
        match openat(
            &directory,
            DB_FILE,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        ) {
            Ok(fd) => File::from(fd),
            Err(Errno::EEXIST) => existing()?,
            Err(error) => return Err(path_error(error)),
        }
    } else {
        existing()?
    };
    private(&file, false)?;
    let identity = file.metadata().map_err(|_| StoreError::Unavailable)?;
    // SQLite resolves `/proc/self/fd` itself, so NOFOLLOW would refuse it;
    // the directory's own path is checked against the FD instead.
    let resolved = std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .map_err(|_| StoreError::Unavailable)?;
    let path = resolved.join(DB_FILE);
    let mode = if create {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let connection = Connection::open_with_flags(
        &path,
        mode | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sql)?;
    let opened = std::fs::symlink_metadata(&path).map_err(|_| StoreError::Unavailable)?;
    if (opened.dev(), opened.ino()) != (identity.dev(), identity.ino()) {
        return Err(StoreError::Unsafe);
    }
    Ok((directory, connection))
}

/// The active revision as one runnable document, read without writing the db
/// whether or not a daemon holds it open.
pub(crate) fn export(data_dir: &Path, with_secrets: bool) -> Result<String, StoreError> {
    let (_directory, mut connection) = connect(data_dir, false)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(2000))
        .map_err(sql)?;
    let application_id: i64 = pragma(&connection, "application_id")?;
    let version: i64 = pragma(&connection, "user_version")?;
    if (application_id, version) != (APPLICATION_ID, SCHEMA_VERSION) {
        return Err(StoreError::Unsupported);
    }
    let (root, revision, secrets) = {
        let transaction = connection.transaction().map_err(sql)?;
        let (_, root, revision) = active_revision(&transaction)?.ok_or(StoreError::Invalid)?;
        let secrets = listener_secrets(&transaction)?;
        transaction.commit().map_err(sql)?;
        (root, revision, secrets)
    };
    let entry = root.join(&revision.sources[0].name);
    let sources = revision
        .sources
        .into_iter()
        .map(|source| (root.join(source.name), Arc::from(source.content)))
        .collect();
    let loaded = Config::from_dae_sources_in_memory(&entry, &sources, limits(), &mut Vec::new())
        .map_err(|_| StoreError::Corrupt)?;
    let text = inline_sources(&loaded.sources).map_err(|_| StoreError::Corrupt)?;
    if with_secrets {
        restore_listener_secrets(&text, &secrets.native_api, &secrets.clash_api)
            .map_err(|_| StoreError::Corrupt)
    } else if secrets == ListenerSecrets::default() {
        Ok(text)
    } else {
        let (text, _) = MaskSet::new(&[], "").with_all(&secrets).mask(&text);
        Ok(format!("# listener secrets omitted\n{text}"))
    }
}

/// Writes `export` to a new 0600 file; an existing `out` is never replaced.
pub(crate) fn export_to(data_dir: &Path, out: &Path, with_secrets: bool) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let text = export(data_dir, with_secrets)
        .map_err(|error| anyhow::anyhow!("configuration db: {error}"))?;
    let name = out
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} names no file", out.display()))?;
    let mut staged = name.to_owned();
    staged.push(format!(".{}.tmp", std::process::id()));
    let staged = out.with_file_name(staged);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&staged)
        .map_err(|error| anyhow::anyhow!("create {}: {error}", staged.display()))?;
    // A hard link publishes the complete file and, unlike rename, never replaces `out`.
    let published = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::hard_link(&staged, out));
    let _ = std::fs::remove_file(&staged);
    published.map_err(|error| anyhow::anyhow!("write {}: {error}", out.display()))?;
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn prepare(connection: &mut Connection) -> Result<(), StoreError> {
    connection
        .busy_timeout(std::time::Duration::from_millis(2000))
        .map_err(sql)?;
    let check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(sql)?;
    if check != "ok" {
        return Err(StoreError::Corrupt);
    }
    let application_id: i64 = pragma(connection, "application_id")?;
    let version: i64 = pragma(connection, "user_version")?;
    let tables: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .map_err(sql)?;
    match (application_id, version, tables) {
        (0, 0, 0) => {}
        (APPLICATION_ID, SCHEMA_VERSION, _) => {}
        (APPLICATION_ID, 0, _) => return Err(StoreError::Corrupt),
        _ => return Err(StoreError::Unsupported),
    }
    for statement in [
        "PRAGMA journal_mode = DELETE",
        "PRAGMA synchronous = FULL",
        "PRAGMA foreign_keys = ON",
    ] {
        connection
            .query_row(statement, [], |_| Ok(()))
            .optional()
            .map_err(sql)?;
    }
    if version == 0 {
        connection
            .execute_batch("PRAGMA auto_vacuum = FULL")
            .map_err(sql)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(sql)?;
        // A concurrent first start may have created the schema since the read above.
        let current: i64 = pragma(&transaction, "user_version")?;
        if current == SCHEMA_VERSION && pragma(&transaction, "application_id")? == APPLICATION_ID {
            return Ok(());
        }
        if current != 0 {
            return Err(StoreError::Unsupported);
        }
        transaction
            .execute_batch(&format!(
                "{SCHEMA}PRAGMA application_id = {APPLICATION_ID};PRAGMA user_version = {SCHEMA_VERSION};"
            ))
            .map_err(sql)?;
        transaction.commit().map_err(sql)?;
    }
    Ok(())
}

fn pragma(connection: &Connection, name: &str) -> Result<i64, StoreError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(sql)
}

fn head_and_parent(connection: &Connection) -> Result<Option<(i64, Option<i64>)>, StoreError> {
    let Some(number) = head(connection)? else {
        return Ok(None);
    };
    let parent = connection
        .query_row(
            "SELECT parent FROM revision WHERE number = ?1",
            [number],
            |row| row.get(0),
        )
        .map_err(sql)?;
    Ok(Some((number, parent)))
}

fn head(connection: &Connection) -> Result<Option<i64>, StoreError> {
    connection
        .query_row("SELECT active FROM head WHERE id = 1", [], |row| row.get(0))
        .optional()
        .map_err(sql)
}

fn active_revision(
    connection: &Connection,
) -> Result<Option<(i64, PathBuf, Revision)>, StoreError> {
    let Some(number) = head(connection)? else {
        return Ok(None);
    };
    let (root, revision) = revision(connection, number)?.ok_or(StoreError::Corrupt)?;
    Ok(Some((number, root, revision)))
}

fn revision(
    connection: &Connection,
    number: i64,
) -> Result<Option<(PathBuf, Revision)>, StoreError> {
    let Some((root, sources, content_sha256, bytes)): Option<(String, String, String, i64)> =
        connection
            .query_row(
                "SELECT root, sources, content_sha256, bytes FROM revision WHERE number = ?1",
                [number],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sql)?
    else {
        return Ok(None);
    };
    let root = lexical(Path::new(&root)).map_err(|_| StoreError::Corrupt)?;
    if digest(sources.as_bytes()) != content_sha256 {
        return Err(StoreError::Corrupt);
    }
    let sources: Vec<StoredSource> =
        serde_json::from_str(&sources).map_err(|_| StoreError::Corrupt)?;
    let total: usize = sources.iter().map(|source| source.content.len()).sum();
    if sources.is_empty()
        || sources.len() > MAX_SOURCES
        || i64::try_from(total).ok() != Some(bytes)
        || sources.iter().enumerate().any(|(index, source)| {
            valid_name(Path::new(&source.name)).is_err()
                || digest(source.content.as_bytes()) != source.sha256
                || match source.parent {
                    None => index != 0,
                    Some(parent) => parent >= index,
                }
        })
    {
        return Err(StoreError::Corrupt);
    }
    Ok(Some((root, Revision { sources })))
}

fn listener_secrets(connection: &Connection) -> Result<ListenerSecrets, StoreError> {
    let mut secrets = ListenerSecrets::default();
    let mut statement = connection
        .prepare("SELECT api, value FROM listener_secret")
        .map_err(sql)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql)?;
    for row in rows {
        let (api, value) = row.map_err(sql)?;
        match api.as_str() {
            "native_api" => secrets.native_api = value,
            "clash_api" => secrets.clash_api = value,
            _ => return Err(StoreError::Corrupt),
        }
    }
    Ok(secrets)
}

fn insert(
    connection: &Connection,
    parent: Option<i64>,
    root: &Path,
    sources: &[StoredSource],
    principal: &str,
    origin: Origin,
) -> Result<i64, StoreError> {
    let text = serde_json::to_string(sources).map_err(|_| StoreError::Invalid)?;
    let bytes: usize = sources.iter().map(|source| source.content.len()).sum();
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64);
    connection
        .execute(
            "INSERT INTO revision (parent, created_at, principal, origin, root, sources, content_sha256, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                parent,
                created_at,
                principal,
                origin.as_str(),
                root.to_str().ok_or(StoreError::Invalid)?,
                text,
                digest(text.as_bytes()),
                i64::try_from(bytes).map_err(|_| StoreError::Invalid)?,
            ],
        )
        .map_err(sql)?;
    Ok(connection.last_insert_rowid())
}

/// Oldest first, until at most `MAX_REVISIONS` and `MAX_RETAINED_BYTES` remain.
fn prune(connection: &Connection, active: i64) -> rusqlite::Result<()> {
    let rows: Vec<(i64, i64)> = connection
        .prepare("SELECT number, bytes FROM revision ORDER BY number DESC")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let (mut kept, mut total, mut full) = (0usize, 0usize, false);
    for (number, bytes) in rows {
        let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
        full |= kept >= MAX_REVISIONS || total.saturating_add(bytes) > MAX_RETAINED_BYTES;
        if full && number != active {
            connection.execute("DELETE FROM revision WHERE number = ?1", [number])?;
        } else {
            kept += 1;
            total = total.saturating_add(bytes);
        }
    }
    Ok(())
}

fn valid_name(name: &Path) -> Result<(), StoreError> {
    let text = name.to_str().ok_or(StoreError::Invalid)?;
    if text.is_empty()
        || text.len() > MAX_NAME_BYTES
        || text.contains('\0')
        || name.components().collect::<PathBuf>() != name
        || name
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || name.extension().and_then(|value| value.to_str()) != Some("dae")
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn lexical(path: &Path) -> Result<PathBuf, StoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(StoreError::Invalid);
    }
    Ok(path.components().collect())
}

fn private(file: &File, directory: bool) -> Result<(), StoreError> {
    let metadata = file.metadata().map_err(|_| StoreError::Unavailable)?;
    let kind = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    if !kind || metadata.uid() != effective_uid() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::Unsafe);
    }
    Ok(())
}

fn path_error(error: Errno) -> StoreError {
    match error {
        Errno::ELOOP | Errno::ENOTDIR => StoreError::Unsafe,
        _ => StoreError::Unavailable,
    }
}

fn log_sql(error: &rusqlite::Error) {
    let code = error.sqlite_error().map(|error| error.extended_code);
    tracing::warn!(sqlite_code = ?code, "configuration database operation failed");
}

fn sql(error: rusqlite::Error) -> StoreError {
    log_sql(&error);
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt) => {
            StoreError::Corrupt
        }
        Some(rusqlite::ErrorCode::CannotOpen) if is_symlink_refusal(&error) => StoreError::Unsafe,
        _ => StoreError::Unavailable,
    }
}

fn is_symlink_refusal(error: &rusqlite::Error) -> bool {
    error
        .sqlite_error()
        .is_some_and(|error| error.extended_code == rusqlite::ffi::SQLITE_CANTOPEN_SYMLINK)
}

fn write_sql(error: rusqlite::Error) -> WriteError {
    log_sql(&error);
    WriteError::Unavailable
}

fn store_unavailable() -> DetailedConfigError {
    DetailedConfigError::new(
        ErrorCategory::Io(std::io::ErrorKind::Other),
        "config-store-unavailable",
        DiagnosticSources::new(None).root(),
        SettingPath::new("config"),
        "configuration store is unavailable",
    )
}

#[cfg(test)]
mod tests;
