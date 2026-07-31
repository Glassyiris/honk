use std::net::IpAddr;

use super::PolicyError;

pub(super) fn exact(value: &str, field: &'static str) -> Result<String, PolicyError> {
    if value.is_empty() {
        return Err(PolicyError::EmptyName { field });
    }
    Ok(value.to_string())
}

pub(super) fn lowercase(value: &str, field: &'static str) -> Result<String, PolicyError> {
    if value.is_empty() {
        return Err(PolicyError::EmptyName { field });
    }
    Ok(value.to_lowercase())
}

pub(super) fn host(value: &str) -> Result<String, PolicyError> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let normalized = value.trim().trim_end_matches('.').to_lowercase();
    if normalized.is_empty() {
        return Err(PolicyError::EmptyName {
            field: "endpoint host",
        });
    }
    if normalized.contains(':')
        || normalized.chars().any(char::is_whitespace)
        || normalized.split('.').any(str::is_empty)
    {
        return Err(PolicyError::InvalidHost {
            value: value.to_string(),
        });
    }
    Ok(normalized)
}
