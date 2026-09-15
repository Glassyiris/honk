use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Include error: {0}")]
    Include(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Unknown node protocol: {0}")]
    UnknownProtocol(String),

    #[error("Unsupported policy: {0}")]
    UnsupportedPolicy(String),
}

/// The legacy exhaustive matching surface, without an input-bearing payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Io(std::io::ErrorKind),
    Parse,
    Include,
    Validation,
    Serialization,
    UnknownProtocol,
    UnsupportedPolicy,
}

impl ErrorCategory {
    pub fn of(error: &ConfigError) -> Self {
        match error {
            ConfigError::Io(error) => Self::Io(error.kind()),
            ConfigError::Parse(_) => Self::Parse,
            ConfigError::Include(_) => Self::Include,
            ConfigError::Validation(_) => Self::Validation,
            ConfigError::Serialization(_) => Self::Serialization,
            ConfigError::UnknownProtocol(_) => Self::UnknownProtocol,
            ConfigError::UnsupportedPolicy(_) => Self::UnsupportedPolicy,
        }
    }
}

#[derive(Debug, Clone, Error)]
#[error("{setting}: {message}", setting = .diagnostic.setting, message = .diagnostic.message)]
pub struct DetailedConfigError {
    pub category: ErrorCategory,
    pub diagnostic: Box<crate::diagnostic::DetailedDiagnostic>,
}

impl DetailedConfigError {
    pub fn new(
        category: ErrorCategory,
        code: &'static str,
        source: crate::diagnostic::SourceRef,
        setting: crate::diagnostic::SettingPath,
        message: &'static str,
    ) -> Self {
        let mut diagnostic = crate::diagnostic::DetailedDiagnostic::warning(
            code,
            source,
            setting,
            crate::diagnostic::SafeValue::Redacted,
            message,
        );
        diagnostic.severity = crate::diagnostic::Severity::Error;
        diagnostic.terminal = true;
        Self {
            category,
            diagnostic: Box::new(diagnostic),
        }
    }

    /// Unknown legacy prose is deliberately withheld, including serde/IO sources.
    pub fn from_legacy(error: ConfigError, source: crate::diagnostic::SourceRef) -> Self {
        use crate::diagnostic::SettingPath;
        let category = ErrorCategory::of(&error);
        if matches!(&error, ConfigError::UnsupportedPolicy(message)
            if message == "group policy 'honk' was renamed to 'score'")
        {
            return Self::new(
                category,
                "unsupported-policy",
                source,
                SettingPath::new("groups").field("policy"),
                "group policy 'honk' was renamed to 'score'",
            );
        }
        let text = match &error {
            ConfigError::Parse(text) | ConfigError::Validation(text) => Some(text.as_str()),
            _ => None,
        };
        if let Some(text) = text {
            if let Some(index) = text
                .strip_prefix("global.udp_check_dns[")
                .and_then(|text| text.strip_suffix("]: invalid DNS check target"))
                .and_then(|text| text.parse::<usize>().ok())
            {
                let mut error = Self::new(
                    category,
                    "invalid-dns-check-target",
                    source,
                    SettingPath::new("global")
                        .field("udp_check_dns")
                        .index(index),
                    "DNS check target requires a host and a valid nonzero port; omitted port is 53",
                );
                error.diagnostic.entry_index = Some(index);
                return error;
            }
            for (prefix, suffix, code, message) in [
                (
                    "duplicate VLESS share-link parameter '",
                    "'",
                    "duplicate-vless-parameter",
                    "VLESS share-link controls must occur only once",
                ),
                (
                    "VLESS parameter '",
                    "' is inactive with mux=off",
                    "invalid-config-value",
                    "VLESS multiplex tuning requires an enabled mux; padding uses h2mux and concurrency/UDP policy use xray",
                ),
                (
                    "VLESS parameter '",
                    "' requires mux=xray",
                    "invalid-config-value",
                    "VLESS concurrency and UDP policy controls require mux=xray",
                ),
            ] {
                if let Some(setting) = text
                    .strip_prefix(prefix)
                    .and_then(|text| text.strip_suffix(suffix))
                    .and_then(vless_parameter_setting)
                {
                    return Self::new(category, code, source, setting, message);
                }
            }
            let reason = match text {
                "unknown traffic predicate" => Some((
                    "unknown-traffic-predicate",
                    SettingPath::new("routing").field("rules"),
                    "unknown or malformed traffic predicate; correct the matcher syntax",
                )),
                "invalid hysteria2 hop port list" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("hy2_port_hopping"),
                    "hopping ports must be nonzero, valid ranges, and nonrepeating",
                )),
                "unsupported TUIC UDP relay mode" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("udp_relay_mode"),
                    "TUIC supports only native UDP relay",
                )),
                "unsupported Hysteria2 obfuscation"
                | "conflicting Hysteria2 obfuscation passwords" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("hy2_obfs"),
                    "Hysteria2 obfuscation must use the supported algorithm and agreeing password claims",
                )),
                "unsupported VMess cipher" | "conflicting VMess cipher aliases" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("encryption"),
                    "VMess cipher must be auto or aes-128-gcm; aliases must agree",
                )),
                "unsupported stream transport"
                | "conflicting stream transport aliases"
                | "unsupported VLESS obfs transport"
                | "unsupported VMess obfs transport" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("transport"),
                    "stream transport must be tcp, ws, or grpc; aliases must agree",
                )),
                "invalid certificate verification boolean"
                | "conflicting certificate verification aliases" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("skip_cert_verify"),
                    "certificate verification aliases must be valid agreeing booleans",
                )),
                "conflicting TLS server name parameters" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("sni"),
                    "conflicting TLS server name aliases",
                )),
                "conflicting VLESS flow parameters" | "unsupported VLESS flow" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("flow"),
                    "VLESS flow must be absent, xtls-rprx-vision, or xtls-rprx-vision-udp443; aliases must agree",
                )),
                "unsupported VLESS share-link parameter 'packet-encoding'"
                | "unsupported VLESS share-link parameter 'packet_encoding'"
                | "unsupported VLESS share-link parameter 'packet-addr'"
                | "unsupported VLESS share-link parameter 'packet_addr'"
                | "unsupported VLESS share-link parameter 'xudp'"
                | "unsupported VLESS share-link parameter 'udp-over-tcp'"
                | "unsupported VLESS share-link parameter 'udp_over_tcp'" => Some((
                    "unsupported-vless-parameter",
                    SettingPath::new("nodes").field("packet_encoding"),
                    "unsupported VLESS UDP encoding alias; use packetEncoding=auto, none, xudp, or uot-v2",
                )),
                "unsupported VLESS share-link parameter 'only-tcp'"
                | "unsupported VLESS share-link parameter 'only_tcp'" => Some((
                    "unsupported-vless-parameter",
                    SettingPath::new("nodes").field("network"),
                    "unsupported VLESS network alias; use udp=0 to disable UDP",
                )),
                "unsupported VLESS share-link parameter 'smux'"
                | "unsupported VLESS share-link parameter 'multiplex'"
                | "unsupported VLESS share-link parameter 'brutal'"
                | "unsupported VLESS share-link parameter 'brutal-opts'"
                | "unsupported VLESS share-link parameter 'brutal_opts'"
                | "unsupported VLESS share-link parameter 'max-connections'"
                | "unsupported VLESS share-link parameter 'max_connections'"
                | "unsupported VLESS share-link parameter 'min-streams'"
                | "unsupported VLESS share-link parameter 'min_streams'"
                | "unsupported VLESS share-link parameter 'max-streams'"
                | "unsupported VLESS share-link parameter 'max_streams'" => Some((
                    "unsupported-vless-parameter",
                    SettingPath::new("nodes").field("multiplex"),
                    "unsupported VLESS multiplex parameter; use mux=off, h2mux, or xray and its supported controls",
                )),
                "unsupported VLESS packetEncoding (expected auto, none, xudp, or uot-v2)" => {
                    Some((
                        "invalid-config-value",
                        SettingPath::new("nodes").field("packet_encoding"),
                        "VLESS packetEncoding must be auto, none, xudp, or uot-v2",
                    ))
                }
                "unsupported VLESS mux (expected off, h2mux, or xray)" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("multiplex"),
                    "VLESS mux must be off, h2mux, or xray",
                )),
                "unsupported VLESS padding (expected true or false)" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes")
                        .field("multiplex")
                        .field("padding"),
                    "VLESS padding must be true or false",
                )),
                "VLESS padding requires mux=h2mux" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes")
                        .field("multiplex")
                        .field("padding"),
                    "VLESS padding requires mux=h2mux",
                )),
                "invalid VLESS concurrency" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("multiplex").field("tcp"),
                    "VLESS concurrency must be an integer from -32768 to 32767",
                )),
                "invalid VLESS xudpConcurrency" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("multiplex").field("udp"),
                    "VLESS xudpConcurrency must be an integer from -32768 to 32767",
                )),
                "unsupported VLESS xudpProxyUDP443 (expected reject, skip, or allow)" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("multiplex").field("udp443"),
                    "VLESS xudpProxyUDP443 must be reject, skip, or allow",
                )),
                "unsupported VLESS udp value (expected 1/true or 0/false)"
                | "conflicting VLESS udp parameters" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("network"),
                    "VLESS udp must be 1/true or 0/false; repeated values must agree",
                )),
                "unsupported VLESS xtls value" => Some((
                    "invalid-config-value",
                    SettingPath::new("nodes").field("flow"),
                    "VLESS xtls must be 0 (disabled) or 2 (Vision)",
                )),
                "VLESS vless_mode was removed; use packetEncoding and mux" => Some((
                    "removed-vless-mode",
                    SettingPath::new("nodes").field("vless_mode"),
                    "VLESS vless_mode was removed; use packetEncoding and mux",
                )),
                "dns.hosts_file was removed; use one or more use_host paths" => Some((
                    "removed-dns-hosts-file",
                    SettingPath::new("dns").field("hosts_file"),
                    "hosts_file was removed; use one or more use_host paths",
                )),
                "not a dae config file" => Some((
                    "not-dae-config",
                    SettingPath::new("config"),
                    "not a dae config file",
                )),
                _ if text.starts_with("unclosed block `") => Some((
                    "unclosed-block",
                    SettingPath::new("config"),
                    "unclosed configuration block",
                )),
                _ if text.starts_with("unexpected `{` at line ") => Some((
                    "unexpected-opener",
                    SettingPath::new("config"),
                    "unexpected opening brace",
                )),
                _ if text.starts_with("unknown experimental.udp_nfqueue setting: ") => Some((
                    "unknown-nfqueue-setting",
                    SettingPath::new("experimental").field("udp_nfqueue"),
                    "unknown NFQUEUE setting; only enabled is supported",
                )),
                _ if text.starts_with("unknown experimental setting: ") => Some((
                    "unknown-experimental-setting",
                    SettingPath::new("experimental"),
                    "unknown experimental setting",
                )),
                _ => None,
            };
            if let Some((code, setting, message)) = reason {
                return Self::new(category, code, source, setting, message);
            }
            for (prefix, root, field) in [
                ("global.dial_mode", "global", "dial_mode"),
                ("global.data_dir", "global", "data_dir"),
                ("global.check_interval", "global", "check_interval"),
                ("global.tproxy_mark", "global", "tproxy_mark"),
                ("global.so_mark_from_dae", "global", "so_mark_from_dae"),
                (
                    "invalid udp_warm_node_count",
                    "global",
                    "udp_warm_node_count",
                ),
                (
                    "invalid preconnect_node_count",
                    "global",
                    "preconnect_node_count",
                ),
                (
                    "invalid max_concurrent_dials",
                    "global",
                    "max_concurrent_dials",
                ),
                (
                    "invalid boolean for global.nfqueue_enable",
                    "global",
                    "nfqueue_enable",
                ),
                ("invalid dns.bind", "dns", "bind"),
                ("invalid dns.client_subnet", "dns", "client_subnet"),
                (
                    "invalid boolean for experimental.udp_nfqueue.enabled",
                    "experimental",
                    "udp_nfqueue",
                ),
            ] {
                if text.starts_with(prefix) {
                    return Self::new(
                        category,
                        "invalid-config-value",
                        source,
                        SettingPath::new(root).field(field),
                        match field {
                            "preconnect_node_count" => "expected a nonnegative integer or auto",
                            "max_concurrent_dials" | "udp_warm_node_count" => {
                                "expected a nonnegative integer"
                            }
                            "nfqueue_enable" | "udp_nfqueue" => {
                                "expected true/false, yes/no, 1/0 or on/off"
                            }
                            "client_subnet" => {
                                "expected empty, auto, auto(IPv4), IPv4, or IPv4/prefix"
                            }
                            _ => "invalid configuration value",
                        },
                    );
                }
            }
        }
        let (code, message) = match category {
            ErrorCategory::Io(_) => ("config-io", "configuration IO failed"),
            ErrorCategory::Parse => ("config-parse", "invalid configuration"),
            ErrorCategory::Include => ("config-include", "invalid configuration include"),
            ErrorCategory::Validation => ("config-validation", "configuration validation failed"),
            ErrorCategory::Serialization => {
                ("config-serialization", "configuration serialization failed")
            }
            ErrorCategory::UnknownProtocol => ("unknown-protocol", "unknown node protocol"),
            ErrorCategory::UnsupportedPolicy => ("unsupported-policy", "unsupported group policy"),
        };
        Self::new(category, code, source, SettingPath::new("config"), message)
    }

    pub fn into_legacy(self) -> ConfigError {
        let message = self.to_string();
        match self.category {
            ErrorCategory::Io(kind) => ConfigError::Io(std::io::Error::new(kind, message)),
            ErrorCategory::Parse => ConfigError::Parse(message),
            ErrorCategory::Include => ConfigError::Include(message),
            ErrorCategory::Validation => ConfigError::Validation(message),
            ErrorCategory::Serialization => ConfigError::Serialization(message),
            ErrorCategory::UnknownProtocol => ConfigError::UnknownProtocol(message),
            ErrorCategory::UnsupportedPolicy => ConfigError::UnsupportedPolicy(message),
        }
    }
}

fn vless_parameter_setting(parameter: &str) -> Option<crate::diagnostic::SettingPath> {
    use crate::diagnostic::SettingPath;
    Some(match parameter {
        "packetEncoding" => SettingPath::new("nodes").field("packet_encoding"),
        "mux" => SettingPath::new("nodes").field("multiplex"),
        "padding" => SettingPath::new("nodes")
            .field("multiplex")
            .field("padding"),
        "concurrency" => SettingPath::new("nodes").field("multiplex").field("tcp"),
        "xudpConcurrency" => SettingPath::new("nodes").field("multiplex").field("udp"),
        "xudpProxyUDP443" => SettingPath::new("nodes").field("multiplex").field("udp443"),
        _ => return None,
    })
}
