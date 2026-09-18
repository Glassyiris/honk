use serde::{Deserialize, Serialize};

/// Clash-compatible REST API server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClashApiConfig {
    /// Listen address for the REST API (e.g. "0.0.0.0:9999").
    /// API is disabled when empty.
    #[serde(default)]
    pub external_controller: String,
    /// Path to external UI static files (e.g. "zashboard").
    #[serde(default)]
    pub external_ui: String,
    /// ZIP download URL used when the external UI directory is empty.
    /// An empty value uses the built-in zashboard URL.
    #[serde(default)]
    pub external_ui_download_url: String,
    /// Node or group tag used to download the external UI.
    /// An empty value follows the normal traffic routing decision.
    #[serde(default)]
    pub external_ui_download_detour: String,
    /// Bearer token secret for API authentication.
    /// If empty, authentication is bypassed.
    #[serde(default)]
    pub secret: String,
    /// Default clash mode: "Rule", "Global", "Direct".
    #[serde(default = "default_clash_mode")]
    pub default_mode: String,
}

fn default_clash_mode() -> String {
    "Rule".to_string()
}

impl Default for ClashApiConfig {
    fn default() -> Self {
        Self {
            external_controller: String::new(),
            external_ui: String::new(),
            external_ui_download_url: String::new(),
            external_ui_download_detour: String::new(),
            secret: String::new(),
            default_mode: "Rule".to_string(),
        }
    }
}

/// Cache file for persistent state (FakeIP, DNS cache, mode/selection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheFileConfig {
    /// Enable cache file persistence.
    #[serde(default)]
    pub enabled: bool,
    /// Cache database path. New relative paths resolve below `global.data_dir`;
    /// an existing legacy config-directory path is retained.
    #[serde(default = "default_cache_path")]
    pub path: String,
    /// Unique identifier for this router instance.
    #[serde(default)]
    pub cache_id: String,
    /// Store FakeIP mappings across restarts.
    #[serde(default)]
    pub store_fakeip: bool,
    /// Store DNS cache answers across restarts.
    #[serde(default)]
    pub store_dns: bool,
}

fn default_cache_path() -> String {
    "cache.db".to_string()
}

impl Default for CacheFileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "cache.db".to_string(),
            cache_id: String::new(),
            store_fakeip: false,
            store_dns: false,
        }
    }
}

/// Independent, opt-in native HTTP API. All settings require a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NativeApiConfig {
    pub enabled: bool,
    pub listen: String,
    pub secret: String,
    pub allow_anonymous_loopback: bool,
    pub allow_origins: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub ui: String,
    pub record_flows: bool,
    pub record_traffic: bool,
    pub record_memory: bool,
    pub config_write: bool,
    pub config_content: bool,
    pub writable_includes: Vec<String>,
}

impl Default for NativeApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:9527".into(),
            secret: String::new(),
            allow_anonymous_loopback: false,
            allow_origins: Vec::new(),
            allowed_hosts: Vec::new(),
            ui: String::new(),
            record_flows: true,
            record_traffic: true,
            record_memory: true,
            config_write: false,
            config_content: false,
            writable_includes: Vec::new(),
        }
    }
}

impl NativeApiConfig {
    pub(crate) fn validate_detailed(
        &self,
        source: &crate::diagnostic::SourceRef,
    ) -> Result<(), crate::error::DetailedConfigError> {
        let invalid = |field, message| {
            crate::error::DetailedConfigError::new(
                crate::error::ErrorCategory::Validation,
                "invalid-config-value",
                source.clone(),
                crate::diagnostic::SettingPath::new("experimental")
                    .field("native_api")
                    .field(field),
                message,
            )
        };
        if !self.secret.is_empty() && !valid_native_bearer_token(&self.secret) {
            return Err(invalid(
                "secret",
                "native API secret must be visible ASCII without commas or whitespace",
            ));
        }
        if (self.config_write || self.config_content) && self.secret.is_empty() {
            return Err(invalid(
                "secret",
                "configuration administration requires a bearer secret",
            ));
        }
        if self.writable_includes.iter().any(|value| {
            let path = std::path::Path::new(value);
            value.is_empty()
                || path.is_absolute()
                || path
                    .components()
                    .any(|part| !matches!(part, std::path::Component::Normal(_)))
                || path.extension().and_then(|value| value.to_str()) != Some("dae")
                || value.contains(['*', '?', '[', ']', '\\'])
        }) {
            return Err(invalid(
                "writable_includes",
                "writable includes must be explicit relative dae paths without traversal or globs",
            ));
        }
        if self.enabled {
            let listen = self
                .listen
                .parse::<std::net::SocketAddr>()
                .ok()
                .filter(|addr| addr.port() != 0)
                .ok_or_else(|| {
                    invalid(
                        "listen",
                        "native API requires a numeric IP and nonzero port",
                    )
                })?;
            if self.secret.is_empty()
                && !(self.allow_anonymous_loopback && listen.ip().is_loopback())
            {
                return Err(invalid(
                    "secret",
                    "native API requires a secret or explicitly anonymous loopback",
                ));
            }
        }
        if self
            .allowed_hosts
            .iter()
            .any(|value| parse_native_authority(value, 80).is_none())
        {
            return Err(invalid(
                "allowed_hosts",
                "expected explicit host authorities without URLs or wildcards",
            ));
        }
        if self
            .allow_origins
            .iter()
            .any(|value| parse_native_origin(value).is_none())
        {
            return Err(invalid(
                "allow_origins",
                "expected explicit HTTP origins without paths or credentials",
            ));
        }
        if self.ui == "embedded" {
            return Err(invalid(
                "ui",
                "embedded native UI is not available; configure a directory",
            ));
        }
        Ok(())
    }
}

/// Credential syntax shared by configuration admission and HTTP authentication.
pub fn valid_native_bearer_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b',')
}

/// Normalize an explicit HTTP authority without DNS resolution or URL rewriting.
pub fn parse_native_authority(value: &str, default_port: u16) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        let ip = host.parse::<std::net::Ipv6Addr>().ok()?;
        let port = if suffix.is_empty() {
            default_port
        } else {
            native_port(suffix.strip_prefix(':')?)?
        };
        return Some((ip.to_string(), port));
    } else if let Some((host, port)) = value.split_once(':') {
        (host, native_port(port)?)
    } else {
        (value, default_port)
    };
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Some((ip.to_string(), port));
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

fn native_port(value: &str) -> Option<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|port| *port != 0)
}

/// Normalize a serialized HTTP origin; paths, credentials and opaque origins are invalid.
pub fn parse_native_origin(value: &str) -> Option<(String, String, u16)> {
    let (scheme, authority) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (host, port) = parse_native_authority(authority, default_port)?;
    Some((scheme, host, port))
}

/// Compatibility-only NFQUEUE settings accepted while old configurations migrate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyUdpNfqueueConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
}

/// Experimental features configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalConfig {
    #[serde(default)]
    pub clash_api: ClashApiConfig,
    #[serde(default)]
    pub cache_file: CacheFileConfig,
    #[serde(default)]
    pub native_api: NativeApiConfig,
    /// Removed from the active schema; accepted only as a migration input.
    #[serde(rename = "udp_nfqueue", default, skip_serializing)]
    pub(crate) legacy_udp_nfqueue: Option<LegacyUdpNfqueueConfig>,
}
