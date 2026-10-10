use super::{DnsConfig, DnsRequestAction, DnsResponseAction, RequestSource};
use crate::diagnostic::{SettingPath, SourceRef};
use crate::error::{DetailedConfigError, ErrorCategory};

impl DnsConfig {
    fn check_upstream_reference(
        &self,
        target: &str,
        source: &SourceRef,
        index: Option<usize>,
        setting: impl FnOnce() -> SettingPath,
    ) -> Result<(), DetailedConfigError> {
        if self.upstream.iter().any(|upstream| upstream.name == target) {
            return Ok(());
        }
        let mut error = DetailedConfigError::new(
            ErrorCategory::Validation,
            "unknown-dns-upstream",
            source.clone(),
            setting(),
            "DNS routing references an undeclared upstream",
        );
        error.diagnostic.entry_index = index.map(|index| index + 1);
        Err(error)
    }

    pub(crate) fn validate_upstream_references_detailed(
        &self,
        source: &SourceRef,
    ) -> Result<(), DetailedConfigError> {
        let routing = &self.routing;
        match routing.request_source() {
            RequestSource::Current => {
                for (index, rule) in routing.request.rules.iter().enumerate() {
                    if let DnsRequestAction::Upstream(target) = &rule.action {
                        self.check_upstream_reference(target, source, Some(index), || {
                            SettingPath::new("dns")
                                .field("routing")
                                .field("request")
                                .field("rules")
                                .index(index + 1)
                                .field("action")
                        })?;
                    }
                }
                if let DnsRequestAction::Upstream(target) = &routing.request.fallback {
                    self.check_upstream_reference(target, source, None, || {
                        SettingPath::new("dns")
                            .field("routing")
                            .field("request")
                            .field("fallback")
                    })?;
                }
            }
            RequestSource::Legacy => {
                for (index, rule) in routing.rules.iter().enumerate() {
                    self.check_upstream_reference(&rule.upstream, source, Some(index), || {
                        SettingPath::new("dns")
                            .field("routing")
                            .field("rules")
                            .index(index + 1)
                            .field("upstream")
                    })?;
                }
                self.check_upstream_reference(&routing.fallback, source, None, || {
                    SettingPath::new("dns").field("routing").field("fallback")
                })
                .map_err(|mut error| {
                    let (code, message) = match routing.fallback.as_str() {
                        "" => (
                            "empty-dns-fallback",
                            "empty legacy DNS fallback has no matching upstream declaration",
                        ),
                        "upstream" => (
                            "missing-dns-fallback",
                            "legacy default fallback 'upstream' requires an upstream declaration",
                        ),
                        _ => return error,
                    };
                    error.diagnostic.code = code;
                    error.diagnostic.message = message;
                    error
                })?;
            }
        }
        for (index, rule) in routing.response.rules.iter().enumerate() {
            if let DnsResponseAction::Upstream(target) = &rule.action {
                self.check_upstream_reference(target, source, Some(index), || {
                    SettingPath::new("dns")
                        .field("routing")
                        .field("response")
                        .field("rules")
                        .index(index + 1)
                        .field("action")
                })?;
            }
        }
        if let DnsResponseAction::Upstream(target) = &routing.response.fallback {
            self.check_upstream_reference(target, source, None, || {
                SettingPath::new("dns")
                    .field("routing")
                    .field("response")
                    .field("fallback")
            })?;
        }
        Ok(())
    }
}
