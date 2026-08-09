//! Runtime data-directory path resolution shared by the engine and handlers.
//!
//! Generated state and relative runtime dependencies use the process-wide
//! directory selected from `global.data_dir`. Existing legacy paths remain
//! usable during upgrades.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Default home for generated state and runtime-supplied assets.
pub const DEFAULT_DATA_DIR: &str = "/var/share/honk";

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Return the configured process-wide runtime data directory.
pub fn data_dir() -> &'static Path {
    DATA_DIR
        .get_or_init(|| PathBuf::from(DEFAULT_DATA_DIR))
        .as_path()
}

/// Install the process-wide runtime data directory.
///
/// Repeating the same value is idempotent. A different value is returned to
/// the caller because path ownership cannot change after runtime consumers
/// have started.
pub fn set_data_dir(path: impl Into<PathBuf>) -> Result<(), PathBuf> {
    let requested = path.into();
    if let Some(configured) = DATA_DIR.get() {
        return if configured == &requested {
            Ok(())
        } else {
            Err(requested)
        };
    }
    match DATA_DIR.set(requested) {
        Ok(()) => Ok(()),
        Err(requested) if DATA_DIR.get() == Some(&requested) => Ok(()),
        Err(requested) => Err(requested),
    }
}

/// Resolve an artifact path for creation or mutation.
///
/// An absolute configured path remains explicit. Every relative path is rooted
/// in the configured data directory so automatic state never depends on the
/// service's working directory.
pub fn resolve_artifact_path(path: impl AsRef<Path>) -> PathBuf {
    resolve_artifact_path_from(path.as_ref(), data_dir())
}

fn resolve_artifact_path_from(path: &Path, data_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        data_dir.join(path)
    }
}

/// Resolve a writable runtime artifact while retaining an existing legacy
/// location during upgrades.
///
/// Absolute paths remain explicit. For a relative path, an existing copy below
/// the configured data directory wins; otherwise an existing `legacy_path` is
/// retained. If neither exists, the returned path is below the configured data
/// directory so new artifacts never depend on the working directory.
pub fn resolve_artifact_path_with_legacy(
    path: impl AsRef<Path>,
    legacy_path: Option<&Path>,
) -> PathBuf {
    resolve_artifact_path_with_legacy_from(path.as_ref(), data_dir(), legacy_path)
}

fn resolve_artifact_path_with_legacy_from(
    path: &Path,
    data_dir: &Path,
    legacy_path: Option<&Path>,
) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    let preferred = data_dir.join(path);
    if preferred.exists() {
        preferred
    } else if let Some(legacy_path) = legacy_path.filter(|path| path.exists()) {
        legacy_path.to_path_buf()
    } else {
        preferred
    }
}

/// Resolve a read-only runtime dependency.
///
/// Absolute paths remain explicit. For a relative path, an existing copy in
/// the configured data directory takes precedence; otherwise an existing
/// legacy working-directory path is retained. A missing path resolves to its
/// intended data-directory location so errors identify the primary lookup.
pub fn resolve_dependency_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    resolve_dependency_path_from(path, data_dir(), path)
}

fn resolve_dependency_path_from(path: &Path, data_dir: &Path, legacy_path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    let preferred = data_dir.join(path);
    if preferred.exists() || !legacy_path.exists() {
        preferred
    } else {
        legacy_path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifacts_root_relative_paths_in_the_data_directory() {
        assert_eq!(
            resolve_artifact_path("cache.db"),
            PathBuf::from("/var/share/honk/cache.db")
        );
        assert_eq!(
            resolve_artifact_path("ui/dashboard"),
            PathBuf::from("/var/share/honk/ui/dashboard")
        );
    }

    #[test]
    fn artifacts_honor_a_custom_data_directory() {
        assert_eq!(
            resolve_artifact_path_from(Path::new("cache.db"), Path::new("/srv/honk")),
            PathBuf::from("/srv/honk/cache.db")
        );
    }

    #[test]
    fn absolute_paths_stay_explicit() {
        assert_eq!(
            resolve_artifact_path("/srv/honk/cache.db"),
            PathBuf::from("/srv/honk/cache.db")
        );
        assert_eq!(
            resolve_dependency_path("/srv/honk/ech.txt"),
            PathBuf::from("/srv/honk/ech.txt")
        );
    }

    #[test]
    fn dependencies_prefer_the_data_directory_then_fall_back() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let legacy = temp.path().join("legacy").join("asset.dat");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, "legacy").unwrap();
        let relative = Path::new("asset.dat");

        assert_eq!(
            resolve_dependency_path_from(relative, &data_dir, &legacy),
            legacy,
            "a legacy working-directory file remains usable"
        );

        let preferred = data_dir.join(relative);
        std::fs::write(&preferred, "data").unwrap();
        assert_eq!(
            resolve_dependency_path_from(relative, &data_dir, &legacy),
            preferred,
            "the data-directory copy wins when both exist"
        );
    }

    #[test]
    fn writable_artifacts_preserve_existing_legacy_paths() {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        let legacy = temp.path().join("legacy").join("cache.db");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, "legacy").unwrap();

        assert_eq!(
            resolve_artifact_path_with_legacy_from(Path::new("cache.db"), &data_dir, Some(&legacy)),
            legacy,
            "an existing legacy artifact remains usable"
        );

        let preferred = data_dir.join("cache.db");
        std::fs::write(&preferred, "data").unwrap();
        assert_eq!(
            resolve_artifact_path_with_legacy_from(Path::new("cache.db"), &data_dir, Some(&legacy)),
            preferred,
            "the data-directory artifact wins when both exist"
        );

        std::fs::remove_file(&preferred).unwrap();
        std::fs::remove_file(&legacy).unwrap();
        assert_eq!(
            resolve_artifact_path_with_legacy_from(Path::new("cache.db"), &data_dir, Some(&legacy)),
            data_dir.join("cache.db"),
            "new artifacts target the data directory"
        );
    }
}
