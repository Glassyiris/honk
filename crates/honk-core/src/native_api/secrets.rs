//! Listener secret values that native API responses must not carry.

use honk_config::{
    Config,
    parser::{SourceSnapshot, cursor::Document, lexer::Source},
};
use serde_json::{Value, json};

/// Shorter secrets are not masked: a one-byte value would erase every
/// occurrence of that byte from every response.
pub(crate) const MIN_MASKED_SECRET: usize = 8;

/// The listener secret values a response must not carry. Building one parses every source that
/// holds an API secret, so `ConfigService` keeps the set for the accepted sources and rebuilds it
/// only when they change.
#[derive(Clone)]
pub(crate) struct ListenerSecrets {
    values: Vec<String>,
    /// Raw spellings borrow values; only distinct JSON escapes need another allocation.
    escaped: Vec<String>,
}

impl ListenerSecrets {
    pub(crate) fn new(sources: &[SourceSnapshot], native_secret: &str) -> Self {
        let mut values = Vec::new();
        if native_secret.len() >= MIN_MASKED_SECRET {
            values.push(native_secret.to_owned());
        }
        for source in sources.iter().filter(|source| source.contains_api_secret) {
            let Ok(document) = Document::parse(
                Source::new(&source.content, source.source.clone()),
                &mut Vec::new(),
            ) else {
                if !source.content.is_empty() {
                    values.push(source.content.to_string());
                }
                continue;
            };
            for field in document
                .sections()
                .filter(|root| root.header() == "experimental")
                .filter_map(|root| root.body())
                .flatten()
                .filter(|section| matches!(section.header().trim(), "native_api" | "clash_api"))
                .filter_map(|section| section.body())
                .flatten()
            {
                let span = field.header_span();
                let Some((key, value)) = source.content[span.start..span.end].split_once(':')
                else {
                    continue;
                };
                if key.trim() != "secret" {
                    continue;
                }
                let value = value.trim();
                let start = span.start + source.content[span.start..span.end].trim_end().len()
                    - value.len();
                let end = start + value.len();
                let quoted = document
                    .tokens()
                    .iter()
                    .flat_map(|token| &token.quoted)
                    .any(|quote| quote.start == start && quote.end == end);
                let value = if quoted {
                    &source.content[start + 1..end - 1]
                } else {
                    value
                };
                if value.len() >= MIN_MASKED_SECRET {
                    values.push(value.to_owned());
                }
            }
        }
        values.sort_unstable();
        values.dedup();
        values.into_iter().fold(Self::empty(), Self::push)
    }

    pub(crate) fn empty() -> Self {
        Self {
            values: Vec::new(),
            escaped: Vec::new(),
        }
    }

    pub(crate) fn from_config(config: &Config) -> Self {
        Self::empty().with_config(config)
    }

    /// Adds the effective secrets of `config`.
    pub(crate) fn with_config(self, config: &Config) -> Self {
        self.with_secret(&config.experimental.native_api.secret)
            .with_secret(&config.experimental.clash_api.secret)
    }

    /// Adds both effective secrets the configuration db holds.
    pub(crate) fn with_all(self, secrets: &super::store::db::StoredSecrets) -> Self {
        self.with_secret(&secrets.native_api)
            .with_secret(&secrets.clash_api)
    }

    pub(crate) fn with_secret(self, secret: &str) -> Self {
        if secret.len() >= MIN_MASKED_SECRET && !self.values.iter().any(|value| value == secret) {
            return self.push(secret.to_owned());
        }
        self
    }

    fn push(mut self, value: String) -> Self {
        let quoted = serde_json::to_string(&value).expect("listener secret is a string");
        let escaped = &quoted[1..quoted.len() - 1];
        if escaped != value {
            self.escaped.push(escaped.to_owned());
        }
        self.values.push(value);
        self
    }

    fn spellings(&self) -> impl Iterator<Item = &str> {
        self.values
            .iter()
            .chain(self.escaped.iter())
            .map(String::as_str)
    }

    pub(crate) fn contains(&self, text: &str) -> bool {
        self.spellings().any(|secret| text.contains(secret))
    }

    pub(crate) fn mask_borrowed<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        if self.contains(text) {
            std::borrow::Cow::Owned(self.mask(text).0)
        } else {
            std::borrow::Cow::Borrowed(text)
        }
    }

    pub(crate) fn mask(&self, text: &str) -> (String, bool) {
        if !self.contains(text) {
            return (text.to_owned(), false);
        }
        let mut hidden = vec![false; text.len()];
        for secret in self.spellings() {
            let mut offset = 0;
            while let Some(relative) = text[offset..].find(secret) {
                let start = offset + relative;
                hidden[start..start + secret.len()].fill(true);
                offset = start + text[start..].chars().next().unwrap().len_utf8();
            }
        }
        let mut masked = String::new();
        let mut hiding = false;
        for (index, character) in text.char_indices() {
            if hidden[index] {
                if !hiding {
                    masked.push_str("<redacted>");
                }
                if matches!(character, '\r' | '\n') {
                    masked.push(character);
                }
            } else {
                masked.push(character);
            }
            hiding = hidden[index];
        }
        (masked, true)
    }

    fn mask_display(&self, value: &mut Value) -> bool {
        let Some(text) = value.as_str() else {
            return false;
        };
        if !self.contains(text) {
            return false;
        }
        let (masked, changed) = self.mask(text);
        *value = json!(masked);
        changed
    }

    pub(in crate::native_api) fn mask_value(&self, value: &mut Value) -> bool {
        let masked = match value {
            Value::Array(values) => values
                .iter_mut()
                .fold(false, |masked, value| self.mask_value(value) | masked),
            Value::Object(values) => values.iter_mut().fold(false, |masked, (key, value)| {
                let changed = if matches!(
                    key.as_str(),
                    "expression"
                        | "rule_expression"
                        | "domain"
                        | "pname"
                        | "src_mac"
                        | "outbound"
                        | "routed_outbound"
                        | "effective_outbound"
                        | "leaf_node_name"
                        | "member_name"
                        | "target"
                        | "name"
                        | "subscription_tag"
                        | "icon"
                        | "check_url"
                        | "final_outbound"
                        | "from_upstream"
                        | "upstream"
                        | "file"
                        | "path"
                        | "absolute_path"
                        | "url_redacted"
                        | "source_redacted"
                ) {
                    self.mask_display(value)
                } else if key == "chain"
                    && let Some(chain) = value.as_array_mut()
                {
                    chain
                        .iter_mut()
                        .fold(false, |masked, value| self.mask_display(value) | masked)
                } else {
                    self.mask_value(value)
                };
                changed | masked
            }),
            _ => false,
        };
        if masked && let Some(object) = value.as_object_mut() {
            if object.contains_key("trace_status") {
                object.insert("trace_status".into(), json!("partial"));
            }
            if let Some(trace) = object.get_mut("trace").and_then(Value::as_object_mut) {
                trace.insert("status".into(), json!("partial"));
                if let Some(missing) = trace.get_mut("missing").and_then(Value::as_array_mut)
                    && !missing.contains(&json!("redacted"))
                {
                    missing.push(json!("redacted"));
                }
            }
        }
        masked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::SystemTime;

    #[test]
    fn listener_masking_preserves_wire_identifiers_and_enums() {
        let mut value = json!({
            "id": "12345678-abcd-1234-abcd-123456789012",
            "next_cursor": "12345678-abcd-1234-abcd-123456789012:1",
            "network": "tcp",
            "chain": ["node-with-secret"],
            "trace_status": "complete",
            "trace": {"status": "complete", "missing": [], "steps": [
                {"chain": "traffic", "rule_id": "instance-1:2:rule:0", "expression": "pname(node-with-secret)"}
            ]}
        });
        let original = value.clone();
        assert!(ListenerSecrets::new(&[], "with-secret").mask_value(&mut value));
        assert_eq!(value["id"], original["id"]);
        assert_eq!(value["next_cursor"], original["next_cursor"]);
        assert_eq!(value["network"], "tcp");
        assert_eq!(value["chain"][0], "node-<redacted>");
        assert_eq!(value["trace"]["steps"][0]["chain"], "traffic");
        assert_eq!(value["trace"]["steps"][0]["rule_id"], "instance-1:2:rule:0");
        assert_eq!(value["trace_status"], "partial");
        assert_eq!(value["trace"]["missing"], json!(["redacted"]));
        let mut value = json!({"network": "tcp", "expression": "pname(tcpsecret)"});
        assert!(ListenerSecrets::new(&[], "tcpsecret").mask_value(&mut value));
        assert_eq!(value["network"], "tcp");
        assert_eq!(value["expression"], "pname(<redacted>)");
        assert_eq!(
            ListenerSecrets::new(&[], "abababab").mask("ababababab"),
            ("<redacted>".into(), true)
        );
        // Below the minimum a secret is left alone rather than shredding common substrings.
        assert_eq!(
            ListenerSecrets::new(&[], "tcp").mask("l4proto(tcp)"),
            ("l4proto(tcp)".into(), false)
        );
        let secret = "quoted\"token";
        let mut value = json!({"expression": format!("pname({secret:?})")});
        assert!(ListenerSecrets::new(&[], secret).mask_value(&mut value));
        assert_eq!(value["expression"], "pname(\"<redacted>\")");
    }

    #[test]
    fn malformed_credential_source_is_withheld_without_panicking() {
        let content = "experimental { native_api { secret: 'unfinished\n";
        let source = honk_config::parser::SourceSnapshot {
            path: PathBuf::from("/config/auth.dae"),
            content: Arc::from(content),
            parent: None,
            source: honk_config::diagnostic::DiagnosticSources::new(None).root(),
            contains_api_secret: true,
            loaded_at: SystemTime::now(),
        };
        let sources = [source];
        let secrets = super::ListenerSecrets::new(&sources, "listener-token");
        assert_eq!(secrets.mask(content), ("<redacted>\n".into(), true));
        assert_eq!(
            secrets.mask(&format!("before\n{content}after")),
            ("before\n<redacted>\nafter".into(), true)
        );
        assert_eq!(
            secrets.mask("ordinary content"),
            ("ordinary content".into(), false)
        );
    }
}
