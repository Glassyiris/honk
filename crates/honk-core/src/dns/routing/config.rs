use honk_config::dns::{DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsRouting};

pub(super) fn request_upstream(action: &DnsRequestAction) -> Option<&str> {
    match action {
        DnsRequestAction::Reject | DnsRequestAction::AsIs => None,
        DnsRequestAction::Upstream(name) => Some(name),
    }
}

pub(super) fn response_upstream(action: &DnsResponseAction) -> Option<&str> {
    match action {
        DnsResponseAction::Accept | DnsResponseAction::Reject => None,
        DnsResponseAction::Upstream(name) => Some(name),
    }
}

pub(super) fn resolve_request_routing(config: &DnsRouting) -> DnsRequestRouting {
    if !config.request.rules.is_empty() {
        return config.request.clone();
    }
    if !config.rules.is_empty() {
        return config.convert_legacy_rules();
    }
    let mut request = config.request.clone();
    let uses_default = matches!(
        &request.fallback,
        DnsRequestAction::Upstream(name) if name == "default"
    );
    if uses_default && !matches!(config.fallback.as_str(), "" | "upstream" | "default") {
        request.fallback = DnsRequestAction::Upstream(config.fallback.clone());
    }
    request
}
