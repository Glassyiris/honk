use super::{DnsConfig, DnsRequestAction, DnsResponseAction, RequestSource};
use crate::ConfigError;

impl DnsConfig {
    pub(crate) fn validate_upstream_references(&self) -> Result<(), ConfigError> {
        let declared_upstreams = || {
            let mut declared: Vec<_> = self
                .upstream
                .iter()
                .map(|upstream| upstream.name.as_str())
                .collect();
            declared.sort_unstable();
            declared
        };
        let check_upstream = |location: std::fmt::Arguments<'_>, target: &str| {
            if self.upstream.iter().any(|upstream| upstream.name == target) {
                return Ok(());
            }
            let declared = declared_upstreams();
            Err(ConfigError::Validation(format!(
                "{location} references undeclared DNS upstream '{target}' \
                 (declared upstreams: {declared:?}); dae action names are lowercased \
                 before exact lookup against unchanged declarations; legacy targets are matched verbatim"
            )))
        };
        let routing = &self.routing;
        match routing.request_source() {
            RequestSource::Current => {
                for (index, rule) in routing.request.rules.iter().enumerate() {
                    if let DnsRequestAction::Upstream(target) = &rule.action {
                        check_upstream(
                            format_args!("dns.routing.request.rules[{index}].action"),
                            target,
                        )?;
                    }
                }
                if let DnsRequestAction::Upstream(target) = &routing.request.fallback {
                    check_upstream(format_args!("dns.routing.request.fallback"), target)?;
                }
            }
            RequestSource::Legacy => {
                for (index, rule) in routing.rules.iter().enumerate() {
                    check_upstream(
                        format_args!("dns.routing.rules[{index}].upstream"),
                        &rule.upstream,
                    )?;
                }
                let target = routing.fallback.as_str();
                if matches!(target, "" | "upstream")
                    && !self.upstream.iter().any(|upstream| upstream.name == target)
                {
                    let declared = declared_upstreams();
                    let message = if target.is_empty() {
                        format!(
                            "dns.routing.fallback has an empty fallback for active legacy rules \
                             (fallback value ''; declared upstreams: {declared:?})"
                        )
                    } else {
                        format!(
                            "dns.routing.fallback has no fallback declared for the legacy default 'upstream' \
                             (declared upstreams: {declared:?})"
                        )
                    };
                    return Err(ConfigError::Validation(message));
                }
                check_upstream(format_args!("dns.routing.fallback"), target)?;
            }
        }
        for (index, rule) in routing.response.rules.iter().enumerate() {
            if let DnsResponseAction::Upstream(target) = &rule.action {
                check_upstream(
                    format_args!("dns.routing.response.rules[{index}].action"),
                    target,
                )?;
            }
        }
        if let DnsResponseAction::Upstream(target) = &routing.response.fallback {
            check_upstream(format_args!("dns.routing.response.fallback"), target)?;
        }
        Ok(())
    }
}
