//! Static assets embedded at build time or from a trusted administrator directory.
//!
//! The administrator also owns any symlink targets; this is not a sandbox for
//! untrusted uploads or downloaded archives.

use std::{borrow::Cow, io::ErrorKind};

use anyhow::{Context, ensure};
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Redirect, Response},
};
use tower_http::services::{ServeDir, ServeFile};

pub(super) enum Ui {
    Directory(Box<(ServeDir, ServeFile)>),
    #[cfg(feature = "native-ui")]
    Embedded,
}

pub(super) async fn load(path: &str) -> anyhow::Result<Option<Ui>> {
    if path.is_empty() {
        return Ok(None);
    }
    if path == "embedded" {
        #[cfg(feature = "native-ui")]
        return Ok(Some(Ui::Embedded));
        #[cfg(not(feature = "native-ui"))]
        anyhow::bail!("embedded native UI requires the native-ui feature");
    }

    let root = honk_config::paths::resolve_dependency_path(path);
    ensure!(
        tokio::fs::metadata(&root)
            .await
            .context("failed to inspect native UI directory")?
            .is_dir(),
        "native UI path must be a directory"
    );
    let index = root.join("index.html");
    ensure!(
        tokio::fs::metadata(&index)
            .await
            .context("failed to inspect native UI index.html")?
            .is_file(),
        "native UI index.html must be a regular file"
    );
    tokio::fs::File::open(&index)
        .await
        .context("native UI index.html must be readable")?;

    Ok(Some(Ui::Directory(Box::new((
        ServeDir::new(root).append_index_html_on_directories(false),
        ServeFile::new(index),
    )))))
}

impl Ui {
    pub(super) async fn serve(&self, request: Request) -> Response {
        let mut response = self.respond(request).await;
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        // No framing header: dashboards such as LuCI embed the UI in a frame served from another port.
        response
    }

    async fn respond(&self, mut request: Request) -> Response {
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, "GET, HEAD")],
            )
                .into_response();
        }
        let path = request.uri().path();
        if matches!(path, "/" | "/ui") {
            return Redirect::temporary("/ui/").into_response();
        }
        let Some(relative) = path.strip_prefix("/ui/") else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let Some(decoded) = decode_path(relative) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if decoded.starts_with('/')
            || decoded.contains('\\')
            || decoded.chars().any(char::is_control)
            || decoded.split('/').any(|part| matches!(part, "." | ".."))
        {
            return StatusCode::NOT_FOUND.into_response();
        }

        // Only validated navigation paths may reach the UI entry point.
        let navigation = !decoded.contains('.')
            && !matches!(
                decoded.split('/').next(),
                Some("assets" | "fonts" | "icons")
            );
        let (files, index) = match self {
            Self::Directory(directory) => (&directory.0, &directory.1),
            #[cfg(feature = "native-ui")]
            Self::Embedded => {
                return embedded_response(&decoded, navigation, request.method() == Method::HEAD);
            }
        };
        let Some(uri) = request
            .uri()
            .path_and_query()
            .and_then(|value| value.as_str().strip_prefix("/ui"))
            .and_then(|value| value.parse::<Uri>().ok())
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        *request.uri_mut() = uri;
        let result = if navigation {
            files
                .clone()
                .fallback(index.clone())
                .try_call(request)
                .await
        } else {
            files.clone().try_call(request).await
        };
        match result {
            Ok(response) => response.map(Body::new),
            Err(error) => match error.kind() {
                ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::NotADirectory => {
                    StatusCode::NOT_FOUND.into_response()
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            },
        }
    }
}

#[cfg(feature = "native-ui")]
fn embedded_response(path: &str, navigation: bool, head: bool) -> Response {
    static FILES: &[(&str, &[u8])] = include!(concat!(env!("OUT_DIR"), "/native_ui_assets.rs"));

    let path = if path.is_empty() { "index.html" } else { path };
    let Ok(index) = FILES.binary_search_by(|(name, _)| name.cmp(&path)) else {
        return if navigation {
            // The hash router's relative assets and service worker require /ui/.
            Redirect::temporary("/ui/").into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        };
    };
    let (path, bytes) = FILES[index];
    let content_type = match path.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html",
        "js" => "text/javascript",
        "css" => "text/css",
        "svg" => "image/svg+xml",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "woff2" => "font/woff2",
        "png" => "image/png",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    };
    let mut response = Response::new(if head {
        Body::empty()
    } else {
        Body::from(bytes)
    });
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    response
}

fn decode_path(path: &str) -> Option<Cow<'_, str>> {
    if !path.as_bytes().contains(&b'%') {
        return Some(Cow::Borrowed(path));
    }
    let mut bytes = path.bytes();
    let mut decoded = Vec::with_capacity(path.len());
    while let Some(byte) = bytes.next() {
        decoded.push(if byte == b'%' {
            let high = char::from(bytes.next()?).to_digit(16)?;
            let low = char::from(bytes.next()?).to_digit(16)?;
            ((high << 4) | low) as u8
        } else {
            byte
        });
    }
    String::from_utf8(decoded).ok().map(Cow::Owned)
}
