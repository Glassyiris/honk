//! Offline admission consumes captured bytes; it never starts runtime owners.

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use honk_config::Config;
use honk_config::diagnostic::{
    DetailedDiagnostic, SafeValue, SettingPath, SourceRef, finish_attempt,
};
use honk_config::error::{DetailedConfigError, ErrorCategory};
use honk_config::parser::{LoadedConfig, SourceLimits, SourceSnapshot};

use crate::control::ControlPlane;
use crate::dns::forwarder::HostsSourceSet;
use crate::dns::policy::PolicyId;
use crate::dns::routing::DnsRouter;
use crate::routing::{GeoRequirements, GeoSourceSet, Router};
use crate::subscription::{SubscriptionStore, parse_subscription_content_with_diagnostics};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DependencySnapshot {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
    pub(crate) bytes: usize,
    /// A standard runtime asset (geodata) rather than an operator source: it is
    /// still hashed for conflict detection but never counts toward the source
    /// budget, which bounds what an administrator may submit, not what the
    /// engine already loads.
    pub(crate) asset: bool,
}

/// Upper bound for one standard asset read during offline validation. A
/// `geoip.dat` is tens of megabytes; this only guards against a runaway file.
const MAX_ASSET_BYTES: usize = 256 * 1024 * 1024;

impl std::fmt::Debug for DependencySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DependencySnapshot")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

pub(crate) struct ValidatedConfig {
    pub(crate) config: Config,
    pub(crate) sources: Vec<SourceSnapshot>,
    pub(crate) dependencies: Vec<DependencySnapshot>,
}

pub(crate) fn validate(
    loaded: LoadedConfig,
    active: &Config,
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<ValidatedConfig, DetailedConfigError> {
    validate_with_data_dir(
        loaded,
        active,
        honk_config::paths::data_dir(),
        limits,
        diagnostics,
    )
}

fn validate_with_data_dir(
    loaded: LoadedConfig,
    active: &Config,
    data_dir: &Path,
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<ValidatedConfig, DetailedConfigError> {
    let result = validate_inner(loaded, active, data_dir, limits, diagnostics);
    finish_attempt(result, diagnostics)
}

fn validate_inner(
    loaded: LoadedConfig,
    active: &Config,
    data_dir: &Path,
    limits: SourceLimits,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<ValidatedConfig, DetailedConfigError> {
    let LoadedConfig {
        mut config,
        sources,
    } = loaded;
    let Some(entry) = sources.first() else {
        return Err(error(
            &honk_config::diagnostic::DiagnosticSources::new(None).root(),
            "config",
            "missing-config-source",
            "configuration has no entry source",
        ));
    };
    let source = &entry.source;
    let mut capture = Capture::new(&sources, active, data_dir, limits)
        .map_err(|cause| dependency_error(source, "config", cause))?;
    config.append_diagnostics(source.clone(), diagnostics);
    config.validate_detailed().map_err(|mut error| {
        error.diagnostic.source = source.clone();
        error
    })?;
    crate::subscription::validate_subscription_ids(&config.subscriptions).map_err(|_| {
        error(
            source,
            "subscription",
            "invalid-subscription-id",
            "subscription identifiers must be unique and nonzero",
        )
    })?;
    config.ensure_builtin_nodes();

    if config.subscriptions.iter().any(|sub| sub.enabled) {
        // No store yet means no subscription has ever been fetched on this host.
        let store = match SubscriptionStore::open_readonly(&capture.data_dir) {
            Ok(store) => Some(store),
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => None,
            Err(cause) => return Err(dependency_error(source, "subscription", cause)),
        };
        for (index, subscription) in config
            .subscriptions
            .iter()
            .enumerate()
            .filter(|(_, sub)| sub.enabled)
        {
            let cached = match store.as_ref().map(|store| store.open_cached(subscription)) {
                Some(Ok(file)) => Some(file),
                Some(Err(cause)) if cause.kind() != io::ErrorKind::NotFound => {
                    return Err(dependency_error(source, "subscription", cause));
                }
                _ => None,
            };
            // The runtime starts a never-fetched subscription with no nodes and
            // fills it in after the first fetch; offline admission mirrors that
            // instead of refusing the configuration that would add it.
            let Some(cached) = cached else {
                diagnostics.push(DetailedDiagnostic::warning(
                    "subscription-not-fetched",
                    source.clone(),
                    SettingPath::new("subscription").index(index + 1),
                    SafeValue::Redacted,
                    "subscription has not been fetched yet; its nodes join after the first fetch",
                ));
                continue;
            };
            let contents = capture
                .file(cached, true, false)
                .map_err(|cause| dependency_error(source, "subscription", cause))?;
            let contents = std::str::from_utf8(&contents).map_err(|_| {
                error(
                    source,
                    "subscription",
                    "invalid-offline-dependency",
                    "cached subscription is not valid UTF-8",
                )
            })?;
            let mut notices = Vec::new();
            let nodes =
                parse_subscription_content_with_diagnostics(subscription, contents, &mut notices);
            // Decoded-provider coordinates are not coordinates in the referring dae document.
            for mut notice in notices.into_iter().filter(|notice| !notice.terminal) {
                notice.source = source.clone();
                notice.setting = SettingPath::new("subscription").index(index + 1);
                notice.span = None;
                notice.line = None;
                notice.byte_column = None;
                notice.entry_index = None;
                notice.related_indices.clear();
                diagnostics.push(notice);
            }
            config.nodes.extend(nodes.map_err(|_| {
                error(
                    source,
                    "subscription",
                    "invalid-offline-dependency",
                    "cached subscription contains no usable configuration",
                )
            })?);
        }
    }
    // Match the runtime's exact choice: same-fetch active nodes win over cached candidates.
    crate::control::reload::rebase_subscription_nodes(active, &mut config);
    config.validate_assembled().map_err(|mut error| {
        error.diagnostic.source = source.clone();
        error
    })?;

    let dns_requirements = DnsRouter::geo_requirements(&config.dns);
    let requirements = GeoRequirements::for_traffic(&config.routing.rules).union(&dns_requirements);
    let data_dir = capture.data_dir.clone();
    let geo =
        GeoSourceSet::load_captured(&requirements, &data_dir, |path| capture.path(path, true))
            .map_err(|cause| dependency_error(source, "routing", cause))?;
    let hosts = HostsSourceSet::load_captured(&config.dns, |path| capture.text(path))
        .map_err(|cause| dependency_error(source, "dns", cause))?
        .parse()
        .map_err(|cause| dependency_error(source, "dns", cause))?;
    for node in &config.nodes {
        if node
            .tls()
            .is_some_and(|tls| tls.enabled || !tls.alpn.is_empty())
        {
            honk_outbound::tls::validate_connector_config_with_ech_reader(node, |path| {
                capture.text(path).map_err(anyhow::Error::new)
            })
            .map_err(|cause| {
                if let Some(io) = cause
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<io::Error>())
                {
                    dependency_error(source, "node", io::Error::from(io.kind()))
                } else {
                    error(
                        source,
                        "node",
                        "invalid-tls-config",
                        "TLS configuration is invalid",
                    )
                }
            })?;
        }
    }
    let router = Router::new_with_geo_sources(
        &config.routing.rules,
        &config.routing.default_outbound,
        &geo,
    )
    .map_err(|_| {
        error(
            source,
            "routing",
            "invalid-routing-config",
            "routing configuration cannot be compiled",
        )
    })?;
    ControlPlane::compile_routing_plan(&config, &router).map_err(|_| {
        error(
            source,
            "routing",
            "invalid-routing-config",
            "routing configuration cannot be compiled",
        )
    })?;
    DnsRouter::new_with_geo_sources(&config.dns, &geo).map_err(|_| {
        error(
            source,
            "dns",
            "invalid-dns-config",
            "DNS routing configuration cannot be compiled",
        )
    })?;
    PolicyId::from_config_with_artifacts(
        &config.dns,
        &hosts.fingerprint(),
        &geo.fingerprint_for(&dns_requirements),
    )
    .map_err(|_| {
        error(
            source,
            "dns",
            "invalid-dns-config",
            "DNS policy configuration is invalid",
        )
    })?;
    Ok(ValidatedConfig {
        config,
        sources,
        dependencies: capture
            .files
            .into_iter()
            .map(|(snapshot, _)| snapshot)
            .collect(),
    })
}

fn error(
    source: &SourceRef,
    setting: &'static str,
    code: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    DetailedConfigError::new(
        ErrorCategory::Validation,
        code,
        source.clone(),
        SettingPath::new(setting),
        message,
    )
}

fn dependency_error(
    source: &SourceRef,
    setting: &'static str,
    cause: io::Error,
) -> DetailedConfigError {
    let (code, message) = match cause.kind() {
        io::ErrorKind::QuotaExceeded => (
            "config-source-limit",
            "configuration source count exceeds the limit",
        ),
        io::ErrorKind::FileTooLarge => (
            "config-byte-limit",
            "configuration source bytes exceed the limit",
        ),
        io::ErrorKind::PermissionDenied => (
            "offline-dependency-denied",
            "configuration dependency is not authorized or readable",
        ),
        io::ErrorKind::NotFound => (
            "missing-offline-dependency",
            "required offline configuration dependency is unavailable",
        ),
        io::ErrorKind::InvalidData => (
            "invalid-offline-dependency",
            "offline configuration dependency is malformed",
        ),
        _ => (
            "unreadable-offline-dependency",
            "offline configuration dependency cannot be read",
        ),
    };
    DetailedConfigError::new(
        ErrorCategory::Io(cause.kind()),
        code,
        source.clone(),
        SettingPath::new(setting),
        message,
    )
}

struct Capture {
    data_dir: PathBuf,
    roots: Vec<PathBuf>,
    explicitly_allowed: Vec<PathBuf>,
    limits: SourceLimits,
    source_count: usize,
    bytes: usize,
    files: Vec<(DependencySnapshot, Arc<[u8]>)>,
}

impl Capture {
    fn new(
        sources: &[SourceSnapshot],
        active: &Config,
        data_dir: &Path,
        limits: SourceLimits,
    ) -> io::Result<Self> {
        let limits = SourceLimits {
            max_bytes: limits.max_bytes.min(8 * 1024 * 1024),
            max_sources: limits.max_sources.min(32),
        };
        if sources.len() > limits.max_sources {
            return Err(io::ErrorKind::QuotaExceeded.into());
        }
        let bytes = sources
            .iter()
            .try_fold(0usize, |total, source| {
                total.checked_add(source.content.len())
            })
            .filter(|bytes| *bytes <= limits.max_bytes)
            .ok_or(io::ErrorKind::FileTooLarge)?;
        let data_dir = data_dir.to_path_buf();
        let mut roots = Vec::new();
        if let Some(parent) = sources.first().and_then(|source| source.path.parent()) {
            roots.push(fs::canonicalize(parent)?);
        }
        if let Ok(path) = fs::canonicalize(&data_dir) {
            roots.push(path);
        }
        let explicitly_allowed = active
            .dns
            .hosts
            .iter()
            .map(String::as_str)
            .chain(
                active
                    .nodes
                    .iter()
                    .filter_map(|node| node.tls()?.ech_config_path.as_deref()),
            )
            .chain(std::iter::once(honk_config::dns::SYSTEM_HOSTS_PATH))
            .filter_map(|path| {
                fs::canonicalize(honk_config::paths::resolve_dependency_path_from(
                    path, &data_dir,
                ))
                .ok()
            })
            .collect();
        Ok(Self {
            data_dir,
            roots,
            explicitly_allowed,
            limits,
            source_count: sources.len(),
            bytes,
            files: Vec::new(),
        })
    }

    fn text(&mut self, path: &str) -> io::Result<String> {
        let path = honk_config::paths::resolve_dependency_path_from(path, &self.data_dir);
        let bytes = self.path(&path, false)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| io::ErrorKind::InvalidData.into())
    }

    fn authorized(&self, path: &Path) -> bool {
        self.roots.iter().any(|root| path.starts_with(root))
            || self
                .explicitly_allowed
                .iter()
                .any(|allowed| path == allowed)
    }

    fn path(&mut self, path: &Path, standard: bool) -> io::Result<Arc<[u8]>> {
        let canonical = fs::canonicalize(path)?;
        if !standard && !self.authorized(&canonical) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let descriptor = nix::fcntl::open(
            &canonical,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_NONBLOCK
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(io::Error::from)?;
        self.file(File::from(descriptor), standard, standard)
    }

    fn file(&mut self, file: File, trusted: bool, asset: bool) -> io::Result<Arc<[u8]>> {
        let path = fs::canonicalize(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        if !trusted && !self.authorized(&path) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if !asset && self.source_count >= self.limits.max_sources {
            return Err(io::ErrorKind::QuotaExceeded.into());
        }
        if let Some((_, bytes)) = self
            .files
            .iter()
            .find(|(snapshot, _)| snapshot.path == path)
        {
            if asset {
                return Ok(Arc::clone(bytes));
            }
            if bytes.len() > self.limits.max_bytes - self.bytes {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            // Each reference can materialize another hosts body or provider node set.
            self.source_count += 1;
            self.bytes += bytes.len();
            return Ok(Arc::clone(bytes));
        }
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // Standard assets have their own bound: the engine loads them whole at
        // startup regardless of what an administrator submits.
        let remaining = if asset {
            MAX_ASSET_BYTES
        } else {
            self.limits.max_bytes - self.bytes
        };
        if metadata.len() > remaining as u64 {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let mut bytes = Vec::new();
        file.take(remaining as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > remaining {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let snapshot = DependencySnapshot {
            path,
            sha256: super::config::digest(&bytes),
            bytes: bytes.len(),
            asset,
        };
        if !asset {
            self.bytes += bytes.len();
            self.source_count += 1;
        }
        let bytes: Arc<[u8]> = bytes.into();
        self.files.push((snapshot, Arc::clone(&bytes)));
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
