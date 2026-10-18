use std::collections::HashMap;

use super::cursor::Segment;
use super::diagnostics::ParserDiagnostics;
use super::read::{self, Text};
use super::scalars::{
    GLOBAL_KEYS, ListOptions, bool_value, list_value, scalar_error, scalar_warning, strict_bool,
};
use crate::diagnostic::{SettingSegment, Severity};
use crate::experimental::ExperimentalConfig;

const CLASH_API_KEYS: &[&str] = &[
    "external_controller",
    "external_ui",
    "external_ui_download_url",
    "external_ui_download_detour",
    "secret",
    "default_mode",
];
const CACHE_FILE_KEYS: &[&str] = &["enabled", "path", "cache_id", "store_fakeip", "store_dns"];
const UDP_NFQUEUE_KEYS: &[&str] = &["enabled"];
const NATIVE_API_KEYS: &[&str] = &[
    "enabled",
    "listen",
    "secret",
    "password_auth",
    "allow_anonymous_loopback",
    "allow_origins",
    "allowed_hosts",
    "ui",
    "record_flows",
    "record_traffic",
    "record_memory",
    "record_logs",
    "record_dns_log",
    "config_write",
    "geosite_download_url",
    "geoip_download_url",
    "geodata_download_detour",
];

/// Experimental blocks, their keys, and the hint for a key only that block owns.
const EXPERIMENTAL_BLOCKS: [(&str, &[&str], &str); 4] = [
    (
        "clash_api",
        CLASH_API_KEYS,
        "clash API setting belongs inside clash_api { }",
    ),
    (
        "cache_file",
        CACHE_FILE_KEYS,
        "cache file setting belongs inside cache_file { }",
    ),
    (
        "udp_nfqueue",
        UDP_NFQUEUE_KEYS,
        "NFQUEUE setting belongs inside udp_nfqueue { }",
    ),
    (
        "native_api",
        NATIVE_API_KEYS,
        "native API setting belongs inside native_api { }",
    ),
];

/// Diagnostics carry schema names only, so an unknown key is named back only
/// when honk knows it from another section.
fn schema_key(key: &str) -> Option<&'static str> {
    EXPERIMENTAL_BLOCKS
        .iter()
        .map(|(_, keys, _)| *keys)
        .chain([GLOBAL_KEYS])
        .flatten()
        .copied()
        .find(|known| *known == key)
}

fn unknown_experimental_setting(
    text: Text<'_, '_>,
    key: &str,
) -> crate::error::DetailedConfigError {
    let mut error = scalar_error(
        text,
        "unknown-experimental-setting",
        "experimental",
        "unknown experimental setting",
    );
    if let Some(key) = schema_key(key) {
        error.diagnostic.setting.0.push(SettingSegment::Field(key));
        let mut owners = EXPERIMENTAL_BLOCKS
            .iter()
            .filter(|(_, keys, _)| keys.contains(&key));
        // A key several blocks share (`enabled`, `secret`) has no single home.
        if let (Some((_, _, hint)), None) = (owners.next(), owners.next()) {
            error.diagnostic.message = hint;
        }
    }
    error
}

pub(super) fn parse_experimental_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<ExperimentalConfig, super::ParseFailure> {
    let mut config = ExperimentalConfig::default();
    let mut api_location = None;
    for root in section {
        let Some(body) = root.body() else {
            continue;
        };
        for segment in body {
            diagnostics.at_text(Text::segment(&segment));
            let Some(header) = read::block_header(&segment) else {
                let text = Text::segment(&segment);
                let key = text.kv().map_or(text, |(key, _)| key).raw();
                return Err(unknown_experimental_setting(text, key).into());
            };
            let name = header.raw();
            let mut values = HashMap::new();
            let Some(&(_, known_keys, _)) = EXPERIMENTAL_BLOCKS
                .iter()
                .find(|(block, _, _)| *block == name)
            else {
                return Err(unknown_experimental_setting(header, name).into());
            };
            let strict_section = matches!(name, "udp_nfqueue" | "native_api");
            let strict_error = |text, key: &str| {
                let mut error = if name == "native_api" {
                    scalar_error(
                        text,
                        "unknown-native-api-setting",
                        "experimental.native_api",
                        "unknown native API setting",
                    )
                } else {
                    scalar_error(
                        text,
                        "unknown-nfqueue-setting",
                        "experimental.udp_nfqueue",
                        "unknown NFQUEUE setting; only enabled is supported",
                    )
                };
                if let Some(key) = schema_key(key) {
                    error.diagnostic.setting.0.push(SettingSegment::Field(key));
                }
                error
            };
            let lines = if strict_section {
                let mut lines = Vec::new();
                if let Some(body) = segment.body() {
                    for child in body {
                        let text = Text::segment(&child);
                        diagnostics.at_text(text);
                        if let Some(header) = read::block_header(&child) {
                            return Err(strict_error(text, header.raw()).into());
                        }
                        lines.push(text);
                    }
                }
                lines
            } else {
                read::child_statements(&segment, diagnostics, super::cursor::BodySyntax::Statements)
            };
            for line in lines {
                diagnostics.at_text(line);
                let Some((key, value)) = line.kv() else {
                    if strict_section {
                        return Err(strict_error(line, line.raw()).into());
                    }
                    line.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-statement",
                        "unknown scalar statement ignored",
                    );
                    continue;
                };
                if name == "native_api"
                    && matches!(key.raw(), "probe_allowed_cidrs" | "probe_allowed_ports")
                {
                    scalar_warning(
                        key,
                        diagnostics,
                        if key.raw() == "probe_allowed_cidrs" {
                            "experimental.native_api.probe_allowed_cidrs"
                        } else {
                            "experimental.native_api.probe_allowed_ports"
                        },
                        "setting was removed and can be deleted; its value is ignored",
                    );
                    continue;
                }
                if !known_keys.contains(&key.raw()) {
                    if strict_section {
                        return Err(strict_error(line, key.raw()).into());
                    }
                    key.notice(
                        diagnostics,
                        Severity::Warning,
                        "unknown-key",
                        "unknown scalar key ignored",
                    );
                    continue;
                }
                diagnostics.register_field(key.raw(), value);
                if let Some(&(block, key, message)) = crate::diagnostic::LEGACY_ASSETS_KEYS
                    .iter()
                    .find(|(block, legacy, _)| *block == name && *legacy == key.raw())
                {
                    diagnostics.emit(crate::diagnostic::legacy_assets_warning(
                        diagnostics.source(),
                        block,
                        key,
                        message,
                    ));
                }
                if name == "clash_api" && key.raw() == "external_controller" {
                    api_location = Some(diagnostics.field_location("external_controller"));
                }
                value.warn_glued_hash(diagnostics);
                values.insert(key.raw(), value);
            }
            match name {
                "clash_api" => {
                    if let Some(value) = values
                        .get("external_controller")
                        .map(|text| text.unquote().raw())
                    {
                        config.clash_api.external_controller = value.to_owned();
                    }
                    if let Some(value) = values.get("external_ui").map(|text| text.unquote().raw())
                    {
                        config.clash_api.external_ui = value.to_owned();
                    }
                    if let Some(value) = values
                        .get("external_ui_download_url")
                        .map(|text| text.unquote().raw())
                    {
                        config.clash_api.external_ui_download_url = value.to_owned();
                    }
                    if let Some(value) = values
                        .get("external_ui_download_detour")
                        .map(|text| text.unquote().raw())
                    {
                        config.clash_api.external_ui_download_detour = value.to_owned();
                    }
                    if let Some(value) = values.get("secret").map(|text| text.unquote().raw()) {
                        config.clash_api.secret = value.to_owned();
                    }
                    if let Some(value) = values.get("default_mode").map(|text| text.unquote().raw())
                    {
                        config.clash_api.default_mode = value.to_owned();
                    }
                }
                "cache_file" => {
                    if values.contains_key("enabled") {
                        config.cache_file.enabled = Some(bool_value(
                            &values,
                            "enabled",
                            "experimental.cache_file.enabled",
                            diagnostics,
                        ));
                    }
                    if let Some(value) = values.get("path").map(|text| text.unquote().raw()) {
                        config.cache_file.legacy_path = Some(value.to_owned());
                    }
                    if let Some(value) = values.get("cache_id").map(|text| text.unquote().raw()) {
                        config.cache_file.legacy_cache_id = Some(value.to_owned());
                    }
                    if let Some(value) = values.get("store_fakeip") {
                        config.cache_file.legacy_store_fakeip =
                            Some(strict_bool(value.unquote().raw()).unwrap_or(false));
                    }
                    for key in config
                        .cache_file
                        .legacy_keys()
                        .filter(|key| values.contains_key(key))
                    {
                        diagnostics.emit(crate::diagnostic::legacy_cache_file_warning(
                            diagnostics.source(),
                            key,
                        ));
                    }
                    if values.contains_key("store_dns") {
                        config.cache_file.store_dns = bool_value(
                            &values,
                            "store_dns",
                            "experimental.cache_file.store_dns",
                            diagnostics,
                        );
                    }
                }
                "native_api" => {
                    for (key, setting, target) in [
                        (
                            "enabled",
                            "experimental.native_api.enabled",
                            &mut config.native_api.enabled,
                        ),
                        (
                            "record_flows",
                            "experimental.native_api.record_flows",
                            &mut config.native_api.record_flows,
                        ),
                        (
                            "record_traffic",
                            "experimental.native_api.record_traffic",
                            &mut config.native_api.record_traffic,
                        ),
                        (
                            "record_memory",
                            "experimental.native_api.record_memory",
                            &mut config.native_api.record_memory,
                        ),
                        (
                            "record_logs",
                            "experimental.native_api.record_logs",
                            &mut config.native_api.record_logs,
                        ),
                        (
                            "record_dns_log",
                            "experimental.native_api.record_dns_log",
                            &mut config.native_api.record_dns_log,
                        ),
                        (
                            "config_write",
                            "experimental.native_api.config_write",
                            &mut config.native_api.config_write,
                        ),
                        (
                            "allow_anonymous_loopback",
                            "experimental.native_api.allow_anonymous_loopback",
                            &mut config.native_api.allow_anonymous_loopback,
                        ),
                        (
                            "password_auth",
                            "experimental.native_api.password_auth",
                            &mut config.native_api.password_auth,
                        ),
                    ] {
                        if let Some(text) = values.get(key) {
                            *target = strict_bool(text.unquote().raw()).ok_or_else(|| {
                                scalar_error(
                                    *text,
                                    "invalid-config-value",
                                    setting,
                                    "expected true/false, yes/no, 1/0 or on/off",
                                )
                            })?;
                        }
                    }
                    for (key, target) in [
                        ("listen", &mut config.native_api.listen),
                        ("secret", &mut config.native_api.secret),
                        ("ui", &mut config.native_api.ui),
                        (
                            "geosite_download_url",
                            &mut config.native_api.geosite_download_url,
                        ),
                        (
                            "geoip_download_url",
                            &mut config.native_api.geoip_download_url,
                        ),
                        (
                            "geodata_download_detour",
                            &mut config.native_api.geodata_download_detour,
                        ),
                    ] {
                        if let Some(text) = values.get(key) {
                            *target = text.unquote().raw().to_owned();
                        }
                    }
                    for (key, setting, target) in [
                        (
                            "allowed_hosts",
                            "experimental.native_api.allowed_hosts",
                            &mut config.native_api.allowed_hosts,
                        ),
                        (
                            "allow_origins",
                            "experimental.native_api.allow_origins",
                            &mut config.native_api.allow_origins,
                        ),
                    ] {
                        if let Some(text) = values.get(key) {
                            let items = list_value(*text, ListOptions::NEW, diagnostics);
                            let invalid = items.iter().any(|value| {
                                if key == "allowed_hosts" {
                                    crate::experimental::parse_native_authority(value, 80).is_none()
                                } else {
                                    crate::experimental::parse_native_origin(value).is_none()
                                }
                            });
                            if invalid {
                                return Err(scalar_error(
                                    *text,
                                    "invalid-config-value",
                                    setting,
                                    "expected individually quoted nonempty authorities or origins",
                                )
                                .into());
                            }
                            *target = items;
                        }
                    }
                }
                "udp_nfqueue" => {
                    let enabled = values
                        .get("enabled")
                        .map(|text| {
                            strict_bool(text.unquote().raw()).ok_or_else(|| {
                                scalar_error(
                                    *text,
                                    "invalid-config-value",
                                    "experimental.udp_nfqueue",
                                    "expected true/false, yes/no, 1/0 or on/off",
                                )
                            })
                        })
                        .transpose()?;
                    config.legacy_udp_nfqueue = Some(crate::experimental::LegacyUdpNfqueueConfig {
                        enabled: enabled.unwrap_or(false),
                    });
                    diagnostics.emit(crate::diagnostic::legacy_nfqueue_warning(
                        diagnostics.source(),
                    ));
                }
                _ => {
                    return Err(scalar_error(
                        header,
                        "unknown-experimental-setting",
                        "experimental",
                        "unknown experimental setting",
                    )
                    .into());
                }
            }
        }
    }
    if let Some((source, line)) = api_location
        && let Some(mut diagnostic) = config.clash_api.exposure_diagnostic(source)
    {
        diagnostic.line = line;
        diagnostics.output.push(diagnostic);
    }
    Ok(config)
}
