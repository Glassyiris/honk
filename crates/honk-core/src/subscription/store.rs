use std::fs::{self, DirBuilder, File};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use honk_config::diagnostic::{DetailedDiagnostic, report_detailed_diagnostics};
use honk_config::node::Node;
use honk_config::subscription::Subscription;
use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};
use sha2::{Digest as _, Sha256};

use super::{SUBSCRIPTION_STORE_DIR, parse_subscription_content_with_diagnostics};

#[derive(Debug)]
struct StoreDirectory {
    // Retained for diagnostics only. Store I/O stays relative to file.
    root: PathBuf,
    file: File,
}

/// Durable raw subscription bodies keyed by their fetch identity.
#[derive(Clone, Debug)]
pub struct SubscriptionStore {
    directory: Arc<StoreDirectory>,
}

impl SubscriptionStore {
    /// Open the subscription store below `global.data_dir`, retaining an
    /// existing old data-directory or `./.sub` store during upgrades.
    pub fn in_data_dir() -> anyhow::Result<Self> {
        Self::open_with_legacy(
            honk_config::paths::resolve_artifact_path(SUBSCRIPTION_STORE_DIR),
            [
                Path::new(honk_config::paths::LEGACY_DATA_DIR).join(SUBSCRIPTION_STORE_DIR),
                PathBuf::from(SUBSCRIPTION_STORE_DIR),
            ],
        )
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn open_readonly(data_dir: &Path) -> io::Result<Self> {
        let preferred = data_dir.join(SUBSCRIPTION_STORE_DIR);
        let legacy = [
            Path::new(honk_config::paths::LEGACY_DATA_DIR).join(SUBSCRIPTION_STORE_DIR),
            PathBuf::from(SUBSCRIPTION_STORE_DIR),
        ];
        Self::open_readonly_with_legacy(preferred, legacy)
    }

    #[cfg(feature = "native-api")]
    fn open_readonly_with_legacy(preferred: PathBuf, legacy: [PathBuf; 2]) -> io::Result<Self> {
        for (index, root) in std::iter::once(preferred).chain(legacy).enumerate() {
            let opened = open_store_directory(&root).and_then(|file| {
                inspect_store_directory(&file)?;
                Ok(file)
            });
            match opened {
                Ok(file) => {
                    return Ok(Self {
                        directory: Arc::new(StoreDirectory { root, file }),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound || index != 0 => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::from(io::ErrorKind::NotFound))
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn open_cached(&self, sub: &Subscription) -> io::Result<File> {
        open_store_file(&self.directory.file, &subscription_filename(sub))
    }

    pub(super) fn open_with_legacy(
        preferred: PathBuf,
        legacy_roots: [PathBuf; 2],
    ) -> anyhow::Result<Self> {
        match open_store_directory(&preferred) {
            Ok(directory) => return Self::from_opened_directory(preferred, directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("open subscription store: {}", preferred.display()));
            }
        }

        for root in legacy_roots {
            let directory = match open_store_directory(&root) {
                Ok(directory) => directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    tracing::warn!(
                        legacy = %root.display(),
                        %error,
                        "legacy subscription store is unusable; trying the next location"
                    );
                    continue;
                }
            };
            match Self::from_opened_directory(root.clone(), directory) {
                Ok(store) => {
                    tracing::warn!(
                        legacy = %root.display(),
                        preferred = %preferred.display(),
                        "using legacy subscription store; move it to the runtime data directory"
                    );
                    return Ok(store);
                }
                Err(error) => {
                    tracing::warn!(
                        legacy = %root.display(),
                        %error,
                        "legacy subscription store is unusable; trying the next location"
                    );
                }
            }
        }
        Self::open(preferred)
    }

    pub(crate) fn open(root: PathBuf) -> anyhow::Result<Self> {
        let directory = match open_store_directory(&root) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder
                    .recursive(true)
                    .mode(0o700)
                    .create(&root)
                    .with_context(|| format!("create subscription store: {}", root.display()))?;
                open_store_directory(&root).with_context(|| {
                    format!("open newly created subscription store: {}", root.display())
                })?
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("open subscription store: {}", root.display()));
            }
        };
        Self::from_opened_directory(root, directory)
    }

    fn from_opened_directory(root: PathBuf, directory: File) -> anyhow::Result<Self> {
        validate_store_directory(&directory)
            .with_context(|| format!("unusable subscription store: {}", root.display()))?;
        Ok(Self {
            directory: Arc::new(StoreDirectory {
                root,
                file: directory,
            }),
        })
    }

    pub fn root(&self) -> &Path {
        self.directory.root.as_path()
    }

    pub async fn load_nodes(&self, sub: &Subscription) -> anyhow::Result<Option<Vec<Node>>> {
        let mut diagnostics = Vec::new();
        let result = self
            .load_nodes_with_diagnostics(sub, &mut diagnostics)
            .await;
        report_detailed_diagnostics(&diagnostics);
        result
    }

    pub async fn load_nodes_with_diagnostics(
        &self,
        sub: &Subscription,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> anyhow::Result<Option<Vec<Node>>> {
        let filename = subscription_filename(sub);
        let directory = Arc::clone(&self.directory);
        let content =
            match tokio::task::spawn_blocking(move || read_store_file(&directory.file, &filename))
                .await?
            {
                Ok(content) => content,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("read subscription cache in {}", self.root().display())
                    });
                }
            };
        parse_subscription_content_with_diagnostics(sub, &content, diagnostics)
            .map(Some)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    pub(crate) async fn store_content(
        &self,
        sub: &Subscription,
        content: String,
    ) -> anyhow::Result<()> {
        let filename = subscription_filename(sub);
        let directory = Arc::clone(&self.directory);
        tokio::task::spawn_blocking(move || {
            write_store_file(&directory.file, &filename, content.as_bytes())
        })
        .await?
        .with_context(|| format!("write subscription cache in {}", self.root().display()))
    }

    #[cfg(test)]
    pub(super) fn path_for(&self, sub: &Subscription) -> PathBuf {
        self.directory.root.join(subscription_filename(sub))
    }
}

fn subscription_cache_user_agent(sub: &Subscription) -> &str {
    // The request UA may change with the binary; the cache identity must not.
    sub.user_agent.as_deref().unwrap_or_default()
}

/// Full fetch identity, matching the cache filename key: URL plus configured
/// UA plus headers. URL-only reload matching can swap identities between
/// same-URL subscriptions with different fetch options.
pub(crate) fn same_subscription_fetch_identity(a: &Subscription, b: &Subscription) -> bool {
    a.url == b.url
        && subscription_cache_user_agent(a) == subscription_cache_user_agent(b)
        && a.headers == b.headers
}

fn subscription_filename(sub: &Subscription) -> String {
    fn add_part(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    add_part(&mut hasher, sub.url.as_bytes());
    add_part(&mut hasher, subscription_cache_user_agent(sub).as_bytes());
    for header in &sub.headers {
        add_part(&mut hasher, header.key.as_bytes());
        add_part(&mut hasher, header.value.as_bytes());
    }
    use base64::Engine as _;
    format!(
        "{}.sub",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
    )
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    unsafe { libc::geteuid() }
}

fn open_store_directory(root: &Path) -> io::Result<File> {
    open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)
}

fn validate_store_directory(directory: &File) -> anyhow::Result<()> {
    inspect_store_directory(directory)?;
    let metadata = directory.metadata()?;
    if metadata.mode() & 0o7777 != 0o700 {
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn inspect_store_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != effective_uid() || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "subscription store directory is not private to the process",
        ));
    }
    Ok(())
}

fn read_store_file(directory: &File, filename: &str) -> io::Result<String> {
    let mut file = open_store_file(directory, filename)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

fn open_store_file(directory: &File, filename: &str) -> io::Result<File> {
    let descriptor = openat(
        directory,
        filename,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("subscription cache is not a regular file"));
    }
    if metadata.uid() != effective_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "subscription cache is not owned by the process",
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "subscription cache is writable by another user",
        ));
    }
    Ok(file)
}

fn write_store_file(directory: &File, destination: &str, content: &[u8]) -> anyhow::Result<()> {
    let temporary = format!(
        ".{destination}.{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let result = (|| -> anyhow::Result<()> {
        let descriptor = openat(
            directory,
            temporary.as_str(),
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK
                | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )?;
        let mut file = File::from(descriptor);
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(content)?;
        file.sync_all()?;
        renameat(directory, temporary.as_str(), directory, destination)?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(directory, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

#[cfg(all(test, feature = "native-api"))]
mod readonly_tests {
    use super::*;

    #[test]
    fn readonly_open_neither_creates_nor_hardens_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let fallbacks = [temp.path().join("old"), temp.path().join("cwd")];
        assert_eq!(
            SubscriptionStore::open_readonly_with_legacy(root.clone(), fallbacks.clone())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert!(!root.exists());
        assert!(fallbacks.iter().all(|path| !path.exists()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let subscription = Subscription::default();
        let path = root.join(subscription_filename(&subscription));
        fs::write(&path, "socks5://127.0.0.1:1080#cached").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let store = SubscriptionStore::open_readonly_with_legacy(root.clone(), fallbacks).unwrap();
        let mut body = String::new();
        store
            .open_cached(&subscription)
            .unwrap()
            .read_to_string(&mut body)
            .unwrap();
        assert_eq!(body, "socks5://127.0.0.1:1080#cached");
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o7777, 0o755);
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o400);
    }
}
