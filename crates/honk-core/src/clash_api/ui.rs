//! External UI auto-download for the clash API (sing-box
//! `experimental/clashapi/server_resources.go` equivalent).
//!
//! When `experimental.clash_api.external_ui` points at a missing or empty
//! directory, a background task downloads the zashboard dashboard zip from
//! GitHub and extracts it into that directory, stripping the single
//! top-level archive directory. The download never blocks startup and
//! failures only log a warning — `ServeDir` keeps returning 404 until the
//! files land.
//!
//! The download URL defaults to [`DEFAULT_UI_DOWNLOAD_URL`] and can be
//! overridden with the `HONK_UI_DOWNLOAD_URL` environment variable.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default dashboard archive (zashboard release `dist.zip`, latest).
pub const DEFAULT_UI_DOWNLOAD_URL: &str =
    "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip";

/// Environment variable overriding [`DEFAULT_UI_DOWNLOAD_URL`].
pub const UI_DOWNLOAD_URL_ENV: &str = "HONK_UI_DOWNLOAD_URL";

/// HTTP timeout for the archive download.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Spawn a background task that downloads the dashboard when `dir` is
/// missing or empty. Fire-and-forget: outcomes are only logged.
pub fn spawn_ui_download_if_needed(dir: String) {
    tokio::spawn(async move {
        match ensure_external_ui(&dir).await {
            Ok(true) => tracing::info!("external UI downloaded into {}", dir),
            Ok(false) => {}
            Err(e) => tracing::warn!("download external ui error: {:#}", e),
        }
    });
}

/// Ensure `dir` exists and holds the dashboard, downloading it when the
/// directory is missing or empty. Returns `Ok(true)` when a download was
/// performed, `Ok(false)` when the directory was already populated.
pub async fn ensure_external_ui(dir: &str) -> anyhow::Result<bool> {
    if dir.is_empty() {
        return Ok(false);
    }
    let path = Path::new(dir);
    match std::fs::read_dir(path) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                // Already populated — nothing to do.
                return Ok(false);
            }
        }
        Err(_) => std::fs::create_dir_all(path)?,
    }
    download_external_ui(dir, &download_url()).await?;
    Ok(true)
}

/// The configured download URL (env override, then the default constant).
fn download_url() -> String {
    std::env::var(UI_DOWNLOAD_URL_ENV).unwrap_or_else(|_| DEFAULT_UI_DOWNLOAD_URL.to_string())
}

/// Download the archive at `url` and extract it into `dir`. On extraction
/// failure the (possibly partial) directory contents are removed again,
/// matching sing-box's cleanup so the next start retries the download.
pub async fn download_external_ui(dir: &str, url: &str) -> anyhow::Result<()> {
    tracing::info!("downloading external ui from {}", url);
    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()?;
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("download external ui failed: {}", response.status());
    }
    let bytes = response.bytes().await?;
    let dir_owned = dir.to_string();
    let result =
        tokio::task::spawn_blocking(move || extract_ui_zip(&bytes, Path::new(&dir_owned))).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            remove_all_in_directory(Path::new(dir));
            Err(e)
        }
        Err(join_err) => {
            remove_all_in_directory(Path::new(dir));
            Err(anyhow::anyhow!(
                "external ui extraction task failed: {}",
                join_err
            ))
        }
    }
}

/// Extract a zip archive into `output`, stripping the single top-level
/// directory when every entry shares one (GitHub archives always do).
/// Entries with path-traversal components are skipped.
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
        // Reject traversal and empty components (zip-slip guard).
        if components
            .iter()
            .any(|c| c.is_empty() || *c == "." || *c == ".." || c.contains('\\'))
        {
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
        let mut out_file = std::fs::File::create(&save_path)?;
        std::io::copy(&mut file as &mut dyn Read, &mut out_file)?;
    }
    Ok(())
}

/// `true` when every entry in the archive lives under the same top-level
/// directory (sing-box `zipIsInSingleDirectory`).
fn single_top_directory(names: &[String]) -> bool {
    let mut top: Option<&str> = None;
    for name in names {
        let mut parts = name.split('/');
        let Some(first) = parts.next() else {
            return false;
        };
        // An entry without a path separator sits at the archive root.
        if parts.next().is_none() {
            return false;
        }
        match top {
            None => top = Some(first),
            Some(t) if t != first => return false,
            _ => {}
        }
    }
    top.is_some()
}

/// Remove everything inside `directory` (best-effort).
fn remove_all_in_directory(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let _ = std::fs::remove_dir_all(entry.path());
        let _ = std::fs::remove_file(entry.path());
    }
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
        download_external_ui(ui_dir.to_str().unwrap(), &format!("http://{}/ui.zip", addr))
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
        let result = download_external_ui(
            dir.path().to_str().unwrap(),
            &format!("http://{}/bad.zip", addr),
        )
        .await;
        assert!(result.is_err());
        // Partial contents are removed so the next start retries.
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }
}
