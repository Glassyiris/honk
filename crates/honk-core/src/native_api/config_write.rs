//! FD-relative configuration replacement; callers own authorization and dependency admission.

use std::ffi::OsString;
use std::fs::{File, Metadata, Permissions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum WriteError {
    #[error("configuration source changed")]
    Conflict,
    #[error("configuration source is unavailable")]
    Unavailable,
    #[error("configuration source exceeds the size limit")]
    TooLarge,
    #[error("configuration source path is unsafe")]
    UnsafePath,
    #[error("configuration source is not UTF-8")]
    InvalidUtf8,
    #[error("configuration source changed but durability is unconfirmed")]
    ChangedButNotDurable,
}

pub(crate) struct SourceFile {
    directory: File,
    parent_path: PathBuf,
    filename: OsString,
    // Pin the original inode until replacement finishes, including across external renames.
    file: File,
    metadata: Metadata,
    hash: String,
    max_bytes: usize,
    #[cfg(test)]
    sync_fault: Option<SyncFault>,
}

impl SourceFile {
    pub(crate) fn open(path: &Path, max_bytes: usize) -> Result<Self, WriteError> {
        Self::open_inner(path, max_bytes, true)
    }

    pub(crate) fn open_binary(path: &Path, max_bytes: usize) -> Result<Self, WriteError> {
        Self::open_inner(path, max_bytes, false)
    }

    fn open_inner(path: &Path, max_bytes: usize, text: bool) -> Result<Self, WriteError> {
        let path = std::path::absolute(path).map_err(|_| WriteError::Unavailable)?;
        let parent_path = path.parent().ok_or(WriteError::UnsafePath)?.to_owned();
        let filename = path.file_name().ok_or(WriteError::UnsafePath)?.to_owned();
        let directory = open_directory(&parent_path).map_err(path_error)?;
        let file = open_source(&directory, &filename).map_err(path_error)?;
        let metadata = regular_metadata(&file, max_bytes)?;
        let mut bytes = Vec::new();
        (&file)
            .take(read_limit(max_bytes))
            .read_to_end(&mut bytes)
            .map_err(|_| WriteError::Unavailable)?;
        if bytes.len() > max_bytes {
            return Err(WriteError::TooLarge);
        }
        if text && std::str::from_utf8(&bytes).is_err() {
            return Err(WriteError::InvalidUtf8);
        }
        if metadata.len() != bytes.len() as u64
            || !same_version(
                &metadata,
                &file.metadata().map_err(|_| WriteError::Unavailable)?,
            )
        {
            return Err(WriteError::Conflict);
        }
        let hash = crate::configuration::digest(&bytes);
        Ok(Self {
            directory,
            parent_path,
            filename,
            file,
            metadata,
            hash,
            max_bytes,
            #[cfg(test)]
            sync_fault: None,
        })
    }

    /// Lowercase, unquoted SHA-256 of the exact source bytes.
    pub(crate) fn sha256(&self) -> String {
        self.hash.clone()
    }

    pub(crate) fn same_target(&self, other: &Self) -> bool {
        same_inode(&self.metadata, &other.metadata)
    }

    /// The callback must recheck the accepted root and complete dependency set.
    /// Neither this check nor the subsequent rename locks out external editors.
    pub(crate) fn replace(
        self,
        expected_hash: &str,
        content: &str,
        before_rename: impl FnOnce() -> Result<(), WriteError>,
    ) -> Result<(), WriteError> {
        let installed = self
            .stage(expected_hash, content.as_bytes())?
            .replace(before_rename)?;
        if installed.durability_confirmed {
            Ok(())
        } else {
            Err(WriteError::ChangedButNotDurable)
        }
    }

    pub(crate) fn stage(
        self,
        expected_hash: &str,
        content: &[u8],
    ) -> Result<StagedFile, WriteError> {
        if self.hash != expected_hash {
            return Err(WriteError::Conflict);
        }
        if content.len() > self.max_bytes {
            return Err(WriteError::TooLarge);
        }
        let mut temporary = TemporaryFile::create(&self.directory)?;
        temporary
            .file
            .write_all(content)
            .map_err(|_| WriteError::Unavailable)?;
        temporary
            .file
            .set_permissions(Permissions::from_mode(self.metadata.mode() & 0o7777))
            .map_err(|_| WriteError::Unavailable)?;
        #[cfg(test)]
        if self.sync_fault == Some(SyncFault::File) {
            return Err(WriteError::Unavailable);
        }
        temporary
            .file
            .sync_all()
            .map_err(|_| WriteError::Unavailable)?;

        Ok(StagedFile {
            source: self,
            temporary,
            hash: crate::configuration::digest(content),
        })
    }

    pub(crate) fn recheck(&self) -> Result<(), WriteError> {
        let current_directory = open_directory(&self.parent_path).map_err(recheck_error)?;
        let original_directory = self
            .directory
            .metadata()
            .map_err(|_| WriteError::Unavailable)?;
        let current_directory = current_directory
            .metadata()
            .map_err(|_| WriteError::Unavailable)?;
        if !same_inode(&original_directory, &current_directory) {
            return Err(WriteError::Conflict);
        }
        let current = open_source(&self.directory, &self.filename).map_err(recheck_error)?;
        let metadata = regular_metadata(&current, self.max_bytes)?;
        if !same_version(&self.metadata, &metadata)
            || !same_version(
                &self.metadata,
                &self.file.metadata().map_err(|_| WriteError::Unavailable)?,
            )
        {
            return Err(WriteError::Conflict);
        }
        let mut reader = (&current).take(read_limit(self.max_bytes));
        let mut digest = Sha256::new();
        let mut buffer = [0; 8192];
        let mut total = 0u64;
        loop {
            let count = match reader.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(WriteError::Unavailable),
            };
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > self.max_bytes as u64 {
                return Err(WriteError::TooLarge);
            }
            digest.update(&buffer[..count]);
        }
        if total != metadata.len()
            || crate::configuration::encode_digest(&digest.finalize()) != self.hash
            || !same_version(
                &metadata,
                &current.metadata().map_err(|_| WriteError::Unavailable)?,
            )
        {
            return Err(WriteError::Conflict);
        }
        Ok(())
    }
}

pub(crate) struct StagedFile {
    source: SourceFile,
    temporary: TemporaryFile,
    hash: String,
}

pub(crate) struct InstalledFile {
    pub(crate) file: SourceFile,
    pub(crate) durability_confirmed: bool,
}

impl StagedFile {
    pub(crate) fn sha256(&self) -> &str {
        &self.hash
    }

    pub(crate) fn same_target(&self, other: &SourceFile) -> bool {
        self.source.same_target(other)
    }

    pub(crate) fn recheck(&self) -> Result<(), WriteError> {
        self.source.recheck()
    }

    pub(crate) fn modified_at(&self) -> Option<std::time::SystemTime> {
        self.temporary.file.metadata().ok()?.modified().ok()
    }

    pub(crate) fn replace(
        mut self,
        before_rename: impl FnOnce() -> Result<(), WriteError>,
    ) -> Result<InstalledFile, WriteError> {
        self.source.recheck()?;
        before_rename()?;
        self.source.recheck()?;
        renameat(
            &self.source.directory,
            self.temporary.name.as_str(),
            &self.source.directory,
            self.source.filename.as_os_str(),
        )
        .map_err(path_error)?;
        self.temporary.renamed = true;
        let metadata = self
            .temporary
            .file
            .metadata()
            .map_err(|_| WriteError::ChangedButNotDurable)?;
        let durability_confirmed = self.source.directory.sync_all().is_ok();
        #[cfg(test)]
        let durability_confirmed =
            durability_confirmed && self.source.sync_fault != Some(SyncFault::Directory);
        std::mem::swap(&mut self.source.file, &mut self.temporary.file);
        self.source.metadata = metadata;
        self.source.hash = self.hash;
        Ok(InstalledFile {
            file: self.source,
            durability_confirmed,
        })
    }
}

fn read_limit(max_bytes: usize) -> u64 {
    (max_bytes as u64).saturating_add(1)
}

fn open_directory(path: &Path) -> Result<File, Errno> {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut directory = File::from(open(Path::new("/"), flags, Mode::empty())?);
    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            Component::Prefix(_) => return Err(Errno::EINVAL),
        };
        directory = File::from(openat(&directory, name, flags, Mode::empty())?);
    }
    Ok(directory)
}

fn open_source(directory: &File, filename: &OsString) -> Result<File, Errno> {
    openat(
        directory,
        filename.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
}

fn regular_metadata(file: &File, max_bytes: usize) -> Result<Metadata, WriteError> {
    let metadata = file.metadata().map_err(|_| WriteError::Unavailable)?;
    if !metadata.is_file() {
        return Err(WriteError::UnsafePath);
    }
    if metadata.len() > max_bytes as u64 {
        return Err(WriteError::TooLarge);
    }
    Ok(metadata)
}

fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn same_version(a: &Metadata, b: &Metadata) -> bool {
    same_inode(a, b)
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn path_error(error: Errno) -> WriteError {
    match error {
        Errno::ELOOP | Errno::ENOTDIR | Errno::EINVAL => WriteError::UnsafePath,
        _ => WriteError::Unavailable,
    }
}

fn recheck_error(error: Errno) -> WriteError {
    match error {
        Errno::ENOENT => WriteError::Conflict,
        _ => path_error(error),
    }
}

struct TemporaryFile {
    directory: File,
    name: String,
    file: File,
    renamed: bool,
}

impl TemporaryFile {
    fn create(directory: &File) -> Result<Self, WriteError> {
        let directory = directory.try_clone().map_err(|_| WriteError::Unavailable)?;
        let name = format!(".honk-config-{}.tmp", uuid::Uuid::new_v4());
        let descriptor = openat(
            &directory,
            name.as_str(),
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK
                | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(path_error)?;
        Ok(Self {
            directory,
            name,
            file: File::from(descriptor),
            renamed: false,
        })
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.renamed {
            let _ = unlinkat(
                &self.directory,
                self.name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum SyncFault {
    File,
    Directory,
}

#[cfg(test)]
mod tests;
