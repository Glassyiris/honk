//! Atomic external-UI download and publication for the Clash API.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default dashboard archive (zashboard release `dist.zip`, latest).
pub const DEFAULT_UI_DOWNLOAD_URL: &str =
    "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip";

/// Environment variable overriding [`DEFAULT_UI_DOWNLOAD_URL`].
pub const UI_DOWNLOAD_URL_ENV: &str = "HONK_UI_DOWNLOAD_URL";

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Start a non-blocking initial download when the configured directory is empty.
pub fn spawn_ui_download_if_needed(
    dir: String,
    update_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    url: Option<String>,
) {
    tokio::spawn(async move {
        let _update = update_lock.lock().await;
        let result = match url {
            Some(url) => ensure_external_ui_from_url(&dir, &url).await,
            None => ensure_external_ui(&dir).await,
        };
        match result {
            Ok(true) => tracing::info!(directory = %dir, "external UI published"),
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, "external UI startup download failed"),
        }
    });
}

/// Download and publish the UI only when `dir` is missing or empty.
pub async fn ensure_external_ui(dir: &str) -> anyhow::Result<bool> {
    let url = download_url();
    ensure_external_ui_from_url(dir, &url).await
}

async fn ensure_external_ui_from_url(dir: &str, url: &str) -> anyhow::Result<bool> {
    if dir.is_empty() {
        return Ok(false);
    }
    match std::fs::read_dir(dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Ok(false);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    replace_external_ui_from_url(dir, url).await?;
    Ok(true)
}

/// Replace `dir` from the configured environment/default archive URL.
pub async fn replace_external_ui(dir: &str) -> anyhow::Result<()> {
    let url = download_url();
    replace_external_ui_from_url(dir, &url).await
}

/// Download into a sibling staging directory and atomically publish it.
pub async fn replace_external_ui_from_url(dir: &str, url: &str) -> anyhow::Result<()> {
    if dir.is_empty() {
        anyhow::bail!("external UI directory is empty");
    }
    tracing::info!(%url, "downloading external UI");
    let response = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()?
        .get(url)
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("download external UI failed: {}", response.status());
    }
    let bytes = response.bytes().await?;
    let target = PathBuf::from(dir);
    let staging = staging_path(&target)?;
    let extraction_path = staging.clone();
    let extraction = tokio::task::spawn_blocking(move || {
        extract_ui_zip(&bytes, &extraction_path)?;
        validate_external_ui(&extraction_path)
    })
    .await;
    match extraction {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let _ = remove_path(&staging);
            return Err(error);
        }
        Err(error) => {
            let _ = remove_path(&staging);
            return Err(anyhow::anyhow!(
                "external UI extraction task failed: {error}"
            ));
        }
    }

    let publish_target = target.clone();
    let publish_staging = staging.clone();
    let exchanged = match tokio::task::spawn_blocking(move || {
        publish_staging_directory(&publish_target, &publish_staging)
    })
    .await
    {
        Ok(Ok(exchanged)) => exchanged,
        Ok(Err(error)) => {
            let _ = remove_path(&staging);
            return Err(error.into());
        }
        Err(error) => {
            let _ = remove_path(&staging);
            return Err(anyhow::anyhow!(
                "external UI publication task failed: {error}"
            ));
        }
    };
    if exchanged {
        let cleanup = staging.clone();
        match tokio::task::spawn_blocking(move || remove_path(&cleanup)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(path = %staging.display(), %error, "old external UI cleanup failed")
            }
            Err(error) => {
                tracing::warn!(path = %staging.display(), %error, "old external UI cleanup task failed")
            }
        }
    }
    Ok(())
}

fn download_url() -> String {
    std::env::var(UI_DOWNLOAD_URL_ENV).unwrap_or_else(|_| DEFAULT_UI_DOWNLOAD_URL.to_owned())
}

fn staging_path(target: &Path) -> anyhow::Result<PathBuf> {
    let name = target
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("external UI path has no directory name"))?;
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    Ok(parent.join(format!(
        ".{}.honk-stage-{}",
        name.to_string_lossy(),
        uuid::Uuid::new_v4()
    )))
}

fn validate_external_ui(staging: &Path) -> anyhow::Result<()> {
    let index = staging.join("index.html");
    let metadata = std::fs::symlink_metadata(&index)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        anyhow::bail!("external UI archive has no regular non-empty index.html");
    }
    Ok(())
}

fn publish_staging_directory(target: &Path, staging: &Path) -> std::io::Result<bool> {
    if target.try_exists()? {
        rename_exchange(target, staging)?;
        Ok(true)
    } else {
        std::fs::rename(staging, target)?;
        Ok(false)
    }
}

#[cfg(target_os = "linux")]
fn rename_exchange(left: &Path, right: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let left = CString::new(left.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let right = CString::new(right.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // libc omits the renameat2 wrapper on musl; use the Linux syscall ABI directly.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_exchange(_left: &Path, _right: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic external UI exchange requires Linux renameat2",
    ))
}

fn remove_path(path: &Path) -> std::io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Extract a zip archive into `output`, stripping a shared top directory.
pub fn extract_ui_zip(bytes: &[u8], output: &Path) -> anyhow::Result<()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    let names: Vec<String> = archive.file_names().map(str::to_string).collect();
    let trim_top = single_top_directory(&names);

    std::fs::create_dir_all(output)?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }
        let mut components: Vec<&str> = file.name().split('/').collect();
        if trim_top {
            components.remove(0);
        }
        if components.iter().any(|component| {
            component.is_empty()
                || *component == "."
                || *component == ".."
                || component.contains('\\')
        }) {
            continue;
        }
        if components.is_empty() {
            continue;
        }
        let mut save_path = PathBuf::from(output);
        for component in components {
            save_path.push(component);
        }
        if let Some(parent) = save_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut output_file = std::fs::File::create(&save_path)?;
        std::io::copy(&mut file as &mut dyn Read, &mut output_file)?;
    }
    Ok(())
}

fn single_top_directory(names: &[String]) -> bool {
    let mut top: Option<&str> = None;
    for name in names {
        let mut parts = name.split('/');
        let Some(first) = parts.next() else {
            return false;
        };
        if parts.next().is_none() {
            return false;
        }
        match top {
            None => top = Some(first),
            Some(current) if current != first => return false,
            _ => {}
        }
    }
    top.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an in-memory zip with the given (path, contents) entries.
    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, contents) in entries {
            writer.start_file(*name, options).unwrap();
            std::io::Write::write_all(&mut writer, contents).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn extract_strips_single_top_directory() {
        let zip_bytes = make_zip(&[
            ("dist/index.html", b"<html>zashboard</html>".as_slice()),
            ("dist/assets/app.js", b"console.log(1)".as_slice()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_ui_zip(&zip_bytes, dir.path()).unwrap();

        assert_eq!(
            std::fs::read(dir.path().join("index.html")).unwrap(),
            b"<html>zashboard</html>"
        );
        assert_eq!(
            std::fs::read(dir.path().join("assets/app.js")).unwrap(),
            b"console.log(1)"
        );
        // The top-level archive directory must not appear.
        assert!(!dir.path().join("dist").exists());
    }

    #[test]
    fn extract_keeps_layout_without_single_top_directory() {
        let zip_bytes = make_zip(&[
            ("index.html", b"root".as_slice()),
            ("sub/page.js", b"sub".as_slice()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_ui_zip(&zip_bytes, dir.path()).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("index.html")).unwrap(),
            b"root"
        );
        assert_eq!(
            std::fs::read(dir.path().join("sub/page.js")).unwrap(),
            b"sub"
        );
    }

    #[test]
    fn extract_skips_traversal_entries() {
        let zip_bytes = make_zip(&[
            ("top/../evil.txt", b"evil".as_slice()),
            ("top/ok.txt", b"ok".as_slice()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_ui_zip(&zip_bytes, dir.path()).unwrap();
        assert!(!dir.path().join("evil.txt").exists());
        assert!(!dir.path().join("../evil.txt").exists());
        assert_eq!(std::fs::read(dir.path().join("ok.txt")).unwrap(), b"ok");
    }

    /// Raw TCP HTTP server serving `body` once per connection.
    async fn spawn_zip_server(body: Vec<u8>) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn ensure_downloads_into_empty_directory() {
        let zip_bytes = make_zip(&[("dist/index.html", b"<html>y</html>".as_slice())]);
        let addr = spawn_zip_server(zip_bytes).await;
        let dir = tempfile::tempdir().unwrap();
        let ui_dir = dir.path().join("ui");
        // Point the download at a *missing* directory to also cover creation.
        replace_external_ui_from_url(ui_dir.to_str().unwrap(), &format!("http://{}/ui.zip", addr))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(ui_dir.join("index.html")).unwrap(),
            b"<html>y</html>"
        );
    }

    #[tokio::test]
    async fn ensure_skips_populated_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "existing").unwrap();
        // A bogus URL proves no download is attempted for populated dirs.
        let downloaded = ensure_external_ui(dir.path().to_str().unwrap())
            .await
            .unwrap();
        assert!(!downloaded);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("index.html")).unwrap(),
            "existing"
        );
    }

    #[tokio::test]
    async fn failed_download_cleans_partial_directory() {
        let zip_bytes = make_zip(&[("top/ok.txt", b"ok".as_slice())]);
        // Corrupt the archive so extraction fails after a successful GET.
        let garbage = zip_bytes[..zip_bytes.len() / 2].to_vec();
        let addr = spawn_zip_server(garbage).await;
        let dir = tempfile::tempdir().unwrap();
        let result = replace_external_ui_from_url(
            dir.path().to_str().unwrap(),
            &format!("http://{}/bad.zip", addr),
        )
        .await;
        assert!(result.is_err());
        // Partial contents are removed so the next start retries.
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }
    #[tokio::test]
    async fn invalid_index_preserves_existing_tree() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("ui");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.html"), "old-index").unwrap();
        let archive = make_zip(&[("dist/assets/app.js", b"new-asset".as_slice())]);
        let addr = spawn_zip_server(archive).await;

        assert!(
            replace_external_ui_from_url(
                target.to_str().unwrap(),
                &format!("http://{addr}/invalid.zip"),
            )
            .await
            .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(target.join("index.html")).unwrap(),
            "old-index"
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn replacement_exchanges_complete_tree() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("ui");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.html"), "old-index").unwrap();
        std::fs::write(target.join("old-only.txt"), "old").unwrap();
        let archive = make_zip(&[
            ("dist/index.html", b"new-index".as_slice()),
            ("dist/assets/app.js", b"new-asset".as_slice()),
        ]);
        let addr = spawn_zip_server(archive).await;

        replace_external_ui_from_url(
            target.to_str().unwrap(),
            &format!("http://{addr}/valid.zip"),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(target.join("index.html")).unwrap(),
            "new-index"
        );
        assert_eq!(
            std::fs::read_to_string(target.join("assets/app.js")).unwrap(),
            "new-asset"
        );
        assert!(!target.join("old-only.txt").exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn exchange_failure_preserves_existing_target() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("ui");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("index.html"), "old-index").unwrap();
        let missing_staging = root.path().join("missing-staging");

        assert!(publish_staging_directory(&target, &missing_staging).is_err());
        assert_eq!(
            std::fs::read_to_string(target.join("index.html")).unwrap(),
            "old-index"
        );
    }
}
