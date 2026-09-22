//! Exact source edits use the same structural cursor and scalar spans as admission.

use std::collections::HashMap;
use std::ops::Range;

use super::cursor::{BodySyntax, Document};
use super::lexer::Source;
use super::read::{self, Text};
use super::sources::SourceSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupField {
    Policy,
    Default,
    Final,
    Tolerance,
    IdleTimeout,
    InterruptConnections,
}

impl GroupField {
    fn key(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Default => "default",
            Self::Final => "final",
            Self::Tolerance => "tolerance",
            Self::IdleTimeout => "idle_timeout",
            Self::InterruptConnections => "interrupt_connections",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("group source cannot represent the requested edit")]
pub struct GroupSourceError;

fn group_source_indices(documents: &[Document<'_>]) -> HashMap<String, usize> {
    let mut result = HashMap::new();
    for (index, document) in documents.iter().enumerate() {
        for root in document.sections().filter(|root| root.header() == "group") {
            if let Some(body) = root.body_with(BodySyntax::Declarations) {
                for group in body {
                    if let Some(name) = read::block_header(&group) {
                        result.insert(name.raw().to_owned(), index);
                    }
                }
            }
        }
    }
    result
}

/// `None` removes every occurrence of a scalar in the winning declaration,
/// preventing an earlier repeated scalar from becoming effective again.
pub fn edit_group_source(
    source: &SourceSnapshot,
    name: &str,
    changes: &[(GroupField, Option<String>)],
) -> Result<String, GroupSourceError> {
    let document = Document::parse_attempt(
        Source::new(&source.content, source.source.clone()),
        &mut Vec::new(),
        false,
    )
    .map_err(|_| GroupSourceError)?;
    let group = document
        .sections()
        .filter(|root| root.header() == "group")
        .filter_map(|root| root.body_with(BodySyntax::Declarations))
        .flatten()
        .filter(|group| read::block_header(group).is_some_and(|header| header.raw() == name))
        .last()
        .ok_or(GroupSourceError)?;
    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    let mut additions = String::new();
    let newline = if source.content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let line_start = source.content[..group.header_span().start]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    let prefix = &source.content[line_start..group.header_span().start];
    let indent = if prefix
        .chars()
        .all(|character| character == ' ' || character == '\t')
    {
        prefix
    } else {
        ""
    };
    for (index, (field, replacement)) in changes.iter().enumerate() {
        if changes[..index]
            .iter()
            .any(|(previous, _)| previous == field)
        {
            return Err(GroupSourceError);
        }
        let fields: Vec<_> = group
            .body()
            .into_iter()
            .flatten()
            .filter(|statement| !statement.is_block() && !statement.is_ignored())
            .filter_map(|statement| {
                let text = Text::segment(&statement);
                let (key, value) = text.kv()?;
                (key.raw().trim() == field.key()).then_some((text, value.trim()))
            })
            .collect();
        match replacement {
            Some(value) => {
                let preferred = fields
                    .last()
                    .and_then(|(_, text)| text.raw().chars().next())
                    .filter(|quote| matches!(quote, '\'' | '"'));
                let encoded = quote_scalar(value, preferred)?;
                if let Some((_, value)) = fields.last() {
                    edits.push((value.span.start..value.span.end, encoded));
                } else {
                    if !additions.is_empty() {
                        additions.push_str(newline);
                    }
                    additions.push_str(indent);
                    additions.push_str("    ");
                    additions.push_str(field.key());
                    additions.push_str(": ");
                    additions.push_str(&encoded);
                }
            }
            None => {
                for (text, _) in fields {
                    edits.push((
                        line_of(&source.content, text.span.start..text.span.end),
                        String::new(),
                    ));
                }
            }
        }
    }
    if !additions.is_empty() {
        let close = group.span().end - 1;
        match own_line_start(&source.content, close) {
            Some(line_start) => edits.push((line_start..line_start, additions + newline)),
            None => edits.push((
                close..close,
                format!("{newline}{additions}{newline}{indent}"),
            )),
        }
    }
    edits.sort_unstable_by_key(|(range, _)| range.start);
    if edits.windows(2).any(|pair| pair[0].0.end > pair[1].0.start) {
        return Err(GroupSourceError);
    }
    let mut output = source.content.to_string();
    for (range, text) in edits.into_iter().rev() {
        output.replace_range(range, &text);
    }
    Ok(output)
}

fn quote_scalar(value: &str, preferred: Option<char>) -> Result<String, GroupSourceError> {
    if value.chars().any(char::is_control) {
        return Err(GroupSourceError);
    }
    for quote in preferred.into_iter().chain(['\'', '"']) {
        let candidate = format!("{quote}{value}{quote}");
        if super::lexer::quoted_end(candidate.as_bytes(), 0) == Some(candidate.len()) {
            return Ok(candidate);
        }
    }
    Err(GroupSourceError)
}

#[derive(Debug, thiserror::Error)]
#[error("managed source cannot represent the requested edit")]
pub struct ManagedSourceError;

/// Append one validated, explicitly named node without expanding includes.
/// Duplicate names or derived node identities in this source are rejected.
pub fn append_node_source(
    source: &SourceSnapshot,
    name: &str,
    link: &str,
) -> Result<String, ManagedSourceError> {
    let (entry, config) = managed_entry("node", name, link)?;
    let [node] = config.nodes.as_slice() else {
        return Err(ManagedSourceError);
    };
    if node.name != name {
        return Err(ManagedSourceError);
    }
    let document = managed_document(source)?;
    let sections = document
        .sections()
        .filter(|root| root.header() == "node")
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    let nodes = super::entries::parse_node_section(&sections, &mut diagnostics)
        .map_err(|_| ManagedSourceError)?;
    if nodes
        .iter()
        .any(|existing| existing.name == name || existing.id == node.id)
    {
        return Err(ManagedSourceError);
    }
    Ok(append_entry(&document, "node", &entry))
}

/// Remove the unique declaration with this parser-derived node identity.
/// `None` means this source owns no matching declaration; includes are untouched.
pub fn remove_node_source(
    source: &SourceSnapshot,
    id: uuid::Uuid,
) -> Result<Option<String>, ManagedSourceError> {
    let document = managed_document(source)?;
    let sections = document
        .sections()
        .filter(|root| root.header() == "node")
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    let mut target = None;
    let mut duplicate = false;
    super::entries::parse_node_section_indexed(&sections, &mut diagnostics, |node, span| {
        if node.id == id {
            duplicate |= target.replace(span.start..span.end).is_some();
        }
    })
    .map_err(|_| ManagedSourceError)?;
    if duplicate {
        return Err(ManagedSourceError);
    }
    Ok(target.map(|range| {
        let mut output = source.content.to_string();
        output.replace_range(line_of(&source.content, range), "");
        output
    }))
}

/// Append an unfetched HTTP(S) subscription, rejecting duplicate source names.
/// Fetching and whole-candidate admission remain the coordinator's responsibility.
pub fn append_subscription_source(
    source: &SourceSnapshot,
    name: &str,
    url: &str,
) -> Result<String, ManagedSourceError> {
    let (entry, config) = managed_entry("subscription", name, url)?;
    let [subscription] = config.subscriptions.as_slice() else {
        return Err(ManagedSourceError);
    };
    if subscription.name != name
        || subscription.url != url
        || url::Url::parse(url)
            .ok()
            .is_none_or(|url| url.host_str().is_none())
    {
        return Err(ManagedSourceError);
    }
    let document = managed_document(source)?;
    let sections = document
        .sections()
        .filter(|root| root.header() == "subscription")
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    let subscriptions = super::entries::parse_subscription_section(&sections, &mut diagnostics)
        .map_err(|_| ManagedSourceError)?;
    if subscriptions.iter().any(|existing| existing.name == name) {
        return Err(ManagedSourceError);
    }
    Ok(append_entry(&document, "subscription", &entry))
}

/// Match by name and fetch identity (URL, configured UA, headers), never the
/// parser's random subscription UUID or mutable refresh metadata. Ambiguous
/// duplicate declarations and legacy headers owning child entries are rejected.
pub fn remove_subscription_source(
    source: &SourceSnapshot,
    subscription: &crate::subscription::Subscription,
) -> Result<Option<String>, ManagedSourceError> {
    let document = managed_document(source)?;
    let sections = document
        .sections()
        .filter(|root| root.header() == "subscription")
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    let mut target = None;
    let mut ambiguous = false;
    super::entries::parse_subscription_section_indexed(
        &sections,
        &mut diagnostics,
        |existing, span| {
            if existing.name == subscription.name
                && existing.url == subscription.url
                && existing.user_agent.as_deref().unwrap_or_default()
                    == subscription.user_agent.as_deref().unwrap_or_default()
                && existing.headers == subscription.headers
            {
                if let Some(span) = span {
                    ambiguous |= target.replace(span.start..span.end).is_some();
                } else {
                    ambiguous = true;
                }
            }
        },
    )
    .map_err(|_| ManagedSourceError)?;
    if ambiguous {
        return Err(ManagedSourceError);
    }
    Ok(target.map(|range| {
        let mut output = source.content.to_string();
        output.replace_range(line_of(&source.content, range), "");
        output
    }))
}

fn is_blank(byte: &u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// The whole line, newline included, when nothing but blanks shares it with
/// the declaration; deleting that range leaves no empty line behind.
fn line_of(content: &str, declaration: Range<usize>) -> Range<usize> {
    let bytes = content.as_bytes();
    let Some(line_start) = own_line_start(content, declaration.start) else {
        return declaration;
    };
    let mut line_end = declaration.end;
    while bytes.get(line_end).is_some_and(is_blank) {
        line_end += 1;
    }
    match &bytes[line_end..] {
        rest if rest.starts_with(b"\r\n") => line_start..line_end + 2,
        rest if rest.starts_with(b"\n") => line_start..line_end + 1,
        [] => line_start..line_end,
        _ => declaration,
    }
}

/// Start of the line when nothing but blanks precedes `offset` on it.
fn own_line_start(content: &str, offset: usize) -> Option<usize> {
    let line_start = content[..offset].rfind('\n').map_or(0, |end| end + 1);
    content[line_start..offset]
        .bytes()
        .all(|byte| is_blank(&byte))
        .then_some(line_start)
}

fn managed_document(source: &SourceSnapshot) -> Result<Document<'_>, ManagedSourceError> {
    Document::parse_attempt(
        Source::new(&source.content, source.source.clone()),
        &mut Vec::new(),
        false,
    )
    .map_err(|_| ManagedSourceError)
}

fn managed_entry(
    section: &str,
    name: &str,
    value: &str,
) -> Result<(String, crate::Config), ManagedSourceError> {
    if name.trim().is_empty() {
        return Err(ManagedSourceError);
    }
    let value = quote_scalar(value, None).map_err(|_| ManagedSourceError)?;
    let quoted = quote_scalar(name, None).map_err(|_| ManagedSourceError)?;
    let bare = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        .then(|| name.to_owned());
    // A bare key that the section reads back differently (`mux`) keeps its quotes.
    for key in bare.into_iter().chain([quoted]) {
        let entry = format!("{key}: {value}");
        let Ok(config) = super::parse_dae_config_with_detailed_diagnostics(
            &format!("{section} {{\n    {entry}\n}}"),
            &mut Vec::new(),
        ) else {
            continue;
        };
        let names: Vec<&str> = match section {
            "node" => config.nodes.iter().map(|node| node.name.as_str()).collect(),
            _ => config
                .subscriptions
                .iter()
                .map(|subscription| subscription.name.as_str())
                .collect(),
        };
        if names == [name] && config.validate().is_ok() {
            return Ok((entry, config));
        }
    }
    Err(ManagedSourceError)
}

fn append_entry(document: &Document<'_>, section: &str, entry: &str) -> String {
    let content = document.source().text();
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut output = content.to_owned();
    if let Some(root) = document.sections().rfind(|root| root.header() == section) {
        let close = root.span().end - 1;
        match own_line_start(content, close) {
            Some(line_start) => output.insert_str(line_start, &format!("    {entry}{newline}")),
            None => output.insert_str(close, &format!("{newline}    {entry}{newline}")),
        }
    } else {
        if !content.is_empty() && !content.ends_with('\n') {
            output.push_str(newline);
        }
        output.push_str(&format!(
            "{section} {{{newline}    {entry}{newline}}}{newline}"
        ));
    }
    output
}

/// Quote `value` as a dae scalar that reads back unchanged.
pub fn quote_dae_scalar(value: &str) -> Result<String, ManagedSourceError> {
    quote_scalar(value, None).map_err(|_| ManagedSourceError)
}

/// Remove every `secret:` of `experimental.native_api` and `.clash_api`,
/// duplicates and overridden ones included.
pub fn strip_listener_secrets(content: &str) -> Result<String, ManagedSourceError> {
    let document = plain_document(content)?;
    let mut ranges = Vec::new();
    for block in listener_blocks(&document) {
        for field in block.1.body().into_iter().flatten() {
            let text = Text::segment(&field);
            if text.kv().is_some_and(|(key, _)| key.raw() == "secret") {
                ranges.push(line_of(content, text.span.start..text.span.end));
            }
        }
    }
    let mut output = content.to_owned();
    for range in ranges.into_iter().rev() {
        output.replace_range(range, "");
    }
    if super::sources::contains_api_secret(&plain_document(&output)?) {
        return Err(ManagedSourceError);
    }
    Ok(output)
}

/// Put listener secrets back into content without any; an empty value is not
/// written. Each goes into the last block of its API.
pub fn restore_listener_secrets(
    content: &str,
    native_api: &str,
    clash_api: &str,
) -> Result<String, ManagedSourceError> {
    let document = plain_document(content)?;
    if super::sources::contains_api_secret(&document) {
        return Err(ManagedSourceError);
    }
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let blocks = listener_blocks(&document);
    let mut edits = Vec::new();
    for (api, value) in [("native_api", native_api), ("clash_api", clash_api)] {
        if value.is_empty() {
            continue;
        }
        let (_, block) = blocks
            .iter()
            .rfind(|(name, _)| *name == api)
            .ok_or(ManagedSourceError)?;
        let entry = format!("secret: {}", quote_dae_scalar(value)?);
        let close = block.span().end - 1;
        let edit = match own_line_start(content, close) {
            Some(line_start) => {
                let indent = &content[line_start..close];
                (line_start, format!("{indent}    {entry}{newline}"))
            }
            None => (close, format!("{entry} ")),
        };
        edits.push(edit);
    }
    edits.sort_unstable_by_key(|(offset, _)| *offset);
    let mut output = content.to_owned();
    for (offset, text) in edits.into_iter().rev() {
        output.insert_str(offset, &text);
    }
    Ok(output)
}

/// Join preorder sources into one document without their `include` roots,
/// which parses to the same `Config` as the tree.
pub fn inline_sources(sources: &[SourceSnapshot]) -> Result<String, ManagedSourceError> {
    let mut output = String::new();
    for source in sources {
        let document = managed_document(source)?;
        let mut content = source.content.to_string();
        let includes: Vec<_> = document
            .sections()
            .filter(|root| root.header() == "include")
            .map(|root| line_of(&source.content, root.span().start..root.span().end))
            .collect();
        for range in includes.into_iter().rev() {
            content.replace_range(range, "");
        }
        output.push_str(&content);
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
    }
    Ok(output)
}

fn plain_document(content: &str) -> Result<Document<'_>, ManagedSourceError> {
    let source = crate::diagnostic::DiagnosticSources::new(None).root();
    Document::parse_attempt(Source::new(content, source), &mut Vec::new(), false)
        .map_err(|_| ManagedSourceError)
}

fn listener_blocks<'d, 'a>(
    document: &'d Document<'a>,
) -> Vec<(&'d str, super::cursor::Segment<'d, 'a>)> {
    document
        .sections()
        .filter(|root| root.header() == "experimental")
        .filter_map(|root| root.body())
        .flatten()
        .filter_map(|block| {
            let name = read::block_header(&block)?.raw();
            matches!(name, "native_api" | "clash_api").then_some((name, block))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSourceLocation {
    pub source_index: usize,
    pub bytes: Range<usize>,
    pub line: usize,
    pub column: usize,
    /// Comment-free condition display, or `fallback` for the terminal entry.
    pub expression: String,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSourceIndex {
    pub rules: Vec<RuleSourceLocation>,
    pub fallback: Option<RuleSourceLocation>,
}

/// Index the runtime's last group declarations and the real rule parser's
/// ordinals from accepted source bytes, never display strings or file labels.
pub fn source_indices(
    sources: &[SourceSnapshot],
) -> Result<(HashMap<String, usize>, RuleSourceIndex), GroupSourceError> {
    let mut notices = Vec::new();
    let documents = sources
        .iter()
        .map(|source| {
            Document::parse_attempt(
                Source::new(&source.content, source.source.clone()),
                &mut notices,
                false,
            )
            .map_err(|_| GroupSourceError)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let groups = group_source_indices(&documents);
    let sections = documents
        .iter()
        .flat_map(Document::sections)
        .filter(|section| section.header() == "routing")
        .collect::<Vec<_>>();
    let mut result = RuleSourceIndex::default();
    let Some(source) = sources.first() else {
        return Ok((groups, result));
    };
    let mut diagnostics =
        super::diagnostics::ParserDiagnostics::new(&mut notices, source.source.clone());
    super::routing::parse_section_indexed(&sections, &mut diagnostics, |ordinal, statement| {
        let span = statement.span;
        if let Some(index) = sources
            .iter()
            .position(|source| source.source.index() == span.source)
        {
            let (line, column) = documents[index].source().location(span.start);
            let location = RuleSourceLocation {
                source_index: index,
                bytes: span.start..span.end,
                line,
                column,
                expression: if ordinal.is_some() {
                    statement
                        .sub(span.start, statement.find("->").unwrap())
                        .trim()
                        .display()
                } else {
                    "fallback".into()
                },
            };
            if ordinal.is_some() {
                result.rules.push(location);
            } else {
                result.fallback = Some(location);
            }
        }
    })
    .map_err(|_| GroupSourceError)?;
    Ok((groups, result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{SourceLimits, parse_dae_sources};
    use std::{path::PathBuf, sync::Arc};

    fn managed_source(content: &str) -> super::super::LoadedConfig {
        parse_dae_sources(
            &[(PathBuf::from("main.dae"), Arc::from(content))],
            SourceLimits::default(),
            &mut Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn managed_appends_use_last_roots_and_preserve_literal_names_and_crlf() {
        let text = "include { 'child.dae' }\r\nnode {} # first\r\nsubscription {} # first\r\nnode {} # last\r\nsubscription {} # last\r\n# untouched\r\n";
        let loaded = managed_source(text);
        let name = "east's # }: node {";
        let edited = append_node_source(
            &loaded.sources[0],
            name,
            "socks5://127.0.0.1:1080#link-name",
        )
        .unwrap();
        assert_eq!(edited, text.replace("node {} # last", "node {\r\n    \"east's # }: node {\": 'socks5://127.0.0.1:1080#link-name'\r\n} # last"));
        let loaded = managed_source(&edited);
        assert_eq!(loaded.config.nodes[0].name, name);
        let edited = append_subscription_source(
            &loaded.sources[0],
            "paid # east",
            "https://example.test/sub?q=%2F#token",
        )
        .unwrap();
        assert_eq!(edited, loaded.sources[0].content.replace("subscription {} # last", "subscription {\r\n    'paid # east': 'https://example.test/sub?q=%2F#token'\r\n} # last"));
        let config = managed_source(&edited).config;
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "paid # east");
        assert_eq!(
            config.subscriptions[0].url,
            "https://example.test/sub?q=%2F#token"
        );
    }

    #[test]
    fn managed_appends_create_sections_after_unterminated_comments() {
        let loaded = managed_source("# preserved EOF comment");
        let edited =
            append_node_source(&loaded.sources[0], "node", "socks5://127.0.0.1:1080").unwrap();
        assert_eq!(
            edited,
            "# preserved EOF comment\nnode {\n    node: 'socks5://127.0.0.1:1080'\n}\n"
        );
        let loaded = managed_source(&edited);
        let edited =
            append_subscription_source(&loaded.sources[0], "provider", "https://example.test/sub")
                .unwrap();
        let config = managed_source(&edited).config;
        assert_eq!(config.nodes[0].name, "node");
        assert_eq!(config.subscriptions[0].name, "provider");
        let loaded = managed_source(&edited);
        let edited =
            append_node_source(&loaded.sources[0], "mux", "socks5://127.0.0.1:1081").unwrap();
        assert!(edited.contains("    'mux': 'socks5://127.0.0.1:1081'\n"));
        assert_eq!(managed_source(&edited).config.nodes[1].name, "mux");
    }

    #[test]
    fn managed_entries_write_bare_keys_and_delete_whole_lines() {
        for newline in ["\n", "\r\n"] {
            let text = format!(
                "node {{{newline}    a: 'socks5://127.0.0.1:1080'{newline}}}{newline}subscription {{{newline}    a: 'https://example.test/a'{newline}}}{newline}"
            );
            let loaded = managed_source(&text);
            let edited =
                append_node_source(&loaded.sources[0], "lab-1.b", "socks5://127.0.0.1:1081")
                    .unwrap();
            let loaded = managed_source(&edited);
            let edited =
                append_subscription_source(&loaded.sources[0], "lab_2", "https://example.test/b")
                    .unwrap();
            assert_eq!(
                edited,
                text.replace(
                    "1080'",
                    &format!("1080'{newline}    lab-1.b: 'socks5://127.0.0.1:1081'")
                )
                .replace(
                    "test/a'",
                    &format!("test/a'{newline}    lab_2: 'https://example.test/b'")
                )
            );
            let loaded = managed_source(&edited);
            let edited = remove_node_source(&loaded.sources[0], loaded.config.nodes[1].id)
                .unwrap()
                .unwrap();
            let loaded = managed_source(&edited);
            let edited =
                remove_subscription_source(&loaded.sources[0], &loaded.config.subscriptions[1])
                    .unwrap()
                    .unwrap();
            assert_eq!(edited, text);
        }
    }

    #[test]
    fn managed_appends_reject_injection_parse_skips_and_duplicate_identities() {
        let loaded = managed_source(
            "node { old: 'socks5://127.0.0.1:1080' }\nsubscription { old: 'https://example.test/old' }\n",
        );
        let source = &loaded.sources[0];
        for name in [
            "",
            " \t",
            "two'quotes\"",
            "trailing\\",
            "new\n}\nrouting { fallback: block }",
        ] {
            assert!(append_node_source(source, name, "socks5://127.0.0.1:1081").is_err());
            assert!(append_subscription_source(source, name, "https://example.test/new").is_err());
        }
        for link in [
            "unsupported://PRIVATE",
            "socks5://127.0.0.1:badport",
            "socks5://127.0.0.1:1081\nPRIVATE",
        ] {
            let error = append_node_source(source, "new", link).unwrap_err();
            assert!(!format!("{error:?} {error}").contains("PRIVATE"));
        }
        for url in [
            "file:///PRIVATE",
            "https://",
            "https://example.test/PRIVATE\n}",
            "https://example.test/two'quotes\"",
        ] {
            assert!(append_subscription_source(source, "new", url).is_err());
        }
        assert!(append_node_source(source, "old", "socks5://127.0.0.1:1081").is_err());
        assert!(
            append_node_source(source, "new", "socks5://127.0.0.1:1080#different-name").is_err()
        );
        assert!(append_subscription_source(source, "old", "https://example.test/new").is_err());
    }

    #[test]
    fn managed_node_deletion_uses_normalized_identity_and_keeps_nested_siblings() {
        let declaration = "'display # name': 'vless://00000000-0000-0000-0000-000000000001@example.test:443?security=tls&flow=xtls-rprx-vision-udp443'";
        let text = format!(
            "include {{ 'child.dae' }}\r\nnode {{\r\n wrapper {{\r\n  {declaration}# keep this comment\r\n  other: 'socks5://127.0.0.1:1080' # sibling\r\n }}\r\n}}\r\n"
        );
        let loaded = managed_source(&text);
        let id = crate::node::Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.test:443?security=tls&flow=xtls-rprx-vision#different-name").unwrap().id;
        assert_eq!(loaded.config.nodes[0].id, id);
        let edited = remove_node_source(&loaded.sources[0], id).unwrap().unwrap();
        assert_eq!(edited, text.replace(declaration, ""));
        let loaded = managed_source(&edited);
        assert_eq!(loaded.config.nodes.len(), 1);
        assert_eq!(loaded.config.nodes[0].name, "other");
        assert!(
            remove_node_source(&loaded.sources[0], id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn managed_subscription_deletion_matches_fetch_identity_not_parser_uuid() {
        let declaration = "'same # name': 'https://example.test/sub'('agent:A')";
        let text = format!(
            "subscription {{\r\n wrapper {{\r\n  {declaration}# keep\r\n  'same # name': 'https://example.test/sub'('agent:B') # sibling\r\n }}\r\n}}\r\n"
        );
        let loaded = managed_source(&text);
        let mut subscription = loaded.config.subscriptions[0].clone();
        subscription.id = uuid::Uuid::nil();
        subscription.node_count = 100;
        subscription.update_interval = 17;
        let edited = remove_subscription_source(&loaded.sources[0], &subscription)
            .unwrap()
            .unwrap();
        assert_eq!(edited, text.replace(declaration, ""));
        let remaining = managed_source(&edited);
        assert_eq!(remaining.config.subscriptions.len(), 1);
        assert_eq!(
            remaining.config.subscriptions[0].user_agent.as_deref(),
            Some("agent:B")
        );
        assert!(
            remove_subscription_source(&remaining.sources[0], &subscription)
                .unwrap()
                .is_none()
        );
        subscription.user_agent = Some("agent:B".into());
        subscription
            .headers
            .push(crate::subscription::SubscriptionHeader {
                key: "X-Fetch".into(),
                value: "different".into(),
            });
        assert!(
            remove_subscription_source(&remaining.sources[0], &subscription)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn managed_subscription_deletion_owns_blocks_but_not_legacy_wrapper_headers() {
        let declaration =
            "'paid # tag': {\n wrapper { url: 'https://example.test/sub' }\n interval: 30s\n}";
        let text = format!(
            "subscription {{\n {declaration} # keep\n empty: {{}} sibling: {{ url: 'https://example.test/other' }}\n}}\n"
        );
        let loaded = managed_source(&text);
        let mut subscription = loaded.config.subscriptions[0].clone();
        subscription.user_agent = Some(String::new());
        let edited = remove_subscription_source(&loaded.sources[0], &subscription)
            .unwrap()
            .unwrap();
        assert_eq!(edited, text.replace(declaration, ""));
        let loaded = managed_source(&edited);
        assert_eq!(
            loaded
                .config
                .subscriptions
                .iter()
                .map(|sub| sub.name.as_str())
                .collect::<Vec<_>>(),
            ["empty", "sibling"]
        );
        let edited =
            remove_subscription_source(&loaded.sources[0], &loaded.config.subscriptions[0])
                .unwrap()
                .unwrap();
        assert_eq!(edited, loaded.sources[0].content.replace("empty: {}", ""));
        assert_eq!(
            managed_source(&edited).config.subscriptions[0].name,
            "sibling"
        );
        let legacy =
            managed_source("subscription {\n a: b: {\n url: 'https://example.test/sub'\n }\n}\n");
        assert!(
            remove_subscription_source(&legacy.sources[0], &legacy.config.subscriptions[0])
                .is_err()
        );
    }

    #[test]
    fn managed_deletion_rejects_duplicate_declarations_and_never_edits_includes() {
        let text = "node {\n one: 'socks5://127.0.0.1:1080'\n two: 'socks5://127.0.0.1:1080'\n}\nsubscription {\n same: 'https://example.test/sub'\n same: 'https://example.test/sub'\n}\n";
        let loaded = managed_source(text);
        assert!(remove_node_source(&loaded.sources[0], loaded.config.nodes[0].id).is_err());
        assert!(
            remove_subscription_source(&loaded.sources[0], &loaded.config.subscriptions[0])
                .is_err()
        );
        let sources = parse_dae_sources(
            &[
                (
                    PathBuf::from("main.dae"),
                    Arc::from("include { 'child.dae' }"),
                ),
                (PathBuf::from("child.dae"), Arc::from(text)),
            ],
            SourceLimits::default(),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(
            remove_node_source(&sources.sources[0], sources.config.nodes[0].id)
                .unwrap()
                .is_none()
        );
        assert!(
            remove_subscription_source(&sources.sources[0], &sources.config.subscriptions[0])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn exact_group_edit_preserves_crlf_comments_includes_and_last_winners() {
        let main = "include { 'child.dae' }\r\ngroup { G { policy: fallback } }\r\n";
        let child = "# untouched\r\ngroup {\r\n  G {\r\n    policy: 'fallback' # old\r\n    policy: \"urltest\" # winner\r\n    tolerance: 4\r\n    tolerance: 9 # repeated\r\n  }\r\n}\r\n";
        let loaded = parse_dae_sources(
            &[
                (PathBuf::from("main.dae"), Arc::from(main)),
                (PathBuf::from("child.dae"), Arc::from(child)),
            ],
            SourceLimits::default(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(source_indices(&loaded.sources).unwrap().0["G"], 1);
        let edited = edit_group_source(
            &loaded.sources[1],
            "G",
            &[
                (GroupField::Policy, Some("selector".into())),
                (GroupField::Tolerance, None),
                (GroupField::Final, Some("block".into())),
            ],
        )
        .unwrap();
        assert_eq!(
            edited,
            child
                .replace("\"urltest\"", "\"selector\"")
                .replace("    tolerance: 4\r\n", "")
                .replace("tolerance: 9", "")
                .replace("  }\r\n}", "      final: 'block'\r\n  }\r\n}")
        );
        let config = crate::parser::parse_dae_config(&edited).unwrap();
        assert_eq!(config.groups[0].policy, crate::node::GroupPolicy::Selector);
        assert_eq!(loaded.sources[0].content.as_ref(), main);
        let empty = parse_dae_sources(
            &[(PathBuf::from("empty.dae"), Arc::from("group { G {} }"))],
            SourceLimits::default(),
            &mut Vec::new(),
        )
        .unwrap();
        let added = edit_group_source(
            &empty.sources[0],
            "G",
            &[(GroupField::Final, Some("block".into()))],
        )
        .unwrap();
        assert_eq!(
            crate::parser::parse_dae_config(&added).unwrap().groups[0]
                .final_outbound
                .as_deref(),
            Some("block")
        );
    }

    #[test]
    fn group_scalars_keep_inheritance_and_icons_keep_exact_values() {
        for icon in [
            "https://example.test/icon.svg?q=%2F",
            "data:image/svg+xml,%3Csvg/%3E",
        ] {
            let config = crate::parser::parse_dae_config(&format!("group {{\n inherited {{ policy: urltest }}\n explicit {{\n policy: urltest\n tolerance: 7\n idle_timeout: 0\n interrupt_connections: true\n icon: '{icon}'\n }}\n}}\nglobal {{ check_tolerance: 123ms }}")).unwrap();
            assert_eq!(config.groups[0].tolerance, 123);
            assert_eq!(config.groups[1].tolerance, 7);
            assert_eq!(config.groups[1].idle_timeout, Some(0));
            assert!(config.groups[1].interrupt_connections);
            assert_eq!(config.groups[1].icon.as_deref(), Some(icon));
            config.validate_detailed().unwrap();
        }
        for icon in [
            "javascript:PRIVATE",
            "https://PRIVATE@example.test/icon",
            "/PRIVATE/icon",
            "data:PRIVATE",
            &format!("https://example.test/{}", "x".repeat(2048)),
        ] {
            let error = crate::parser::parse_dae_config_with_detailed_diagnostics(
                &format!("group {{ G {{ icon: '{icon}' }} }}"),
                &mut Vec::new(),
            )
            .unwrap_err();
            assert!(!format!("{error:?}").contains("PRIVATE"));
            let config = crate::Config {
                groups: vec![crate::node::Group {
                    name: "G".into(),
                    icon: Some(icon.into()),
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(config.validate_detailed().is_err());
            assert!(config.validate_assembled().is_err());
        }
        for setting in [
            "tolerance: -1",
            "idle_timeout: 1.5",
            "interrupt_connections: maybe",
            "icon { ignored: value }",
        ] {
            assert!(
                crate::parser::parse_dae_config(&format!("group {{ G {{ {setting} }} }}")).is_err()
            );
        }
    }

    #[test]
    fn listener_secrets_strip_and_restore_by_span() {
        let main = "include { 'child.dae' }\nglobal { log_level: info }\nexperimental {\n    native_api {\n        enabled: true\n        secret: 'first-native-token'\n        secret: \"override-native-token\" # kept comment\n    }\n    clash_api {\n        external_controller: '127.0.0.1:9090'\n        secret: \"clash token with spaces\"\n    }\n}\n";
        let child = "experimental { native_api { secret: final-native-token } }";
        let inputs = |main: &str, child: &str| {
            parse_dae_sources(
                &[
                    (PathBuf::from("main.dae"), Arc::from(main)),
                    (PathBuf::from("child.dae"), Arc::from(child)),
                ],
                SourceLimits::default(),
                &mut Vec::new(),
            )
            .unwrap()
        };
        let original = inputs(main, child);
        let native = original.config.experimental.native_api.secret.clone();
        let clash = original.config.experimental.clash_api.secret.clone();
        assert_eq!(
            (native.as_str(), clash.as_str()),
            ("final-native-token", "clash token with spaces")
        );

        let stripped_main = strip_listener_secrets(main).unwrap();
        let stripped_child = strip_listener_secrets(child).unwrap();
        for text in [&stripped_main, &stripped_child] {
            assert!(!text.contains("token"));
        }
        assert!(stripped_main.contains("# kept comment"));
        let stripped = inputs(&stripped_main, &stripped_child);
        assert!(
            stripped
                .sources
                .iter()
                .all(|source| !source.contains_api_secret)
        );
        let mut resupplied = stripped.config.clone();
        resupplied.experimental.native_api.secret = native.clone();
        resupplied.experimental.clash_api.secret = clash.clone();
        assert_eq!(resupplied, original.config);

        let inlined = inline_sources(&original.sources).unwrap();
        assert!(!inlined.contains("include"));
        assert_eq!(
            crate::parser::parse_dae_config(&inlined).unwrap(),
            original.config
        );

        let restored =
            restore_listener_secrets(&inline_sources(&stripped.sources).unwrap(), &native, &clash)
                .unwrap();
        assert_eq!(
            crate::parser::parse_dae_config(&restored).unwrap(),
            original.config
        );
        assert!(restore_listener_secrets(main, &native, &clash).is_err());
    }

    #[test]
    fn routing_positions_follow_parser_ordinals_across_includes() {
        let first = "routing {\r\n # not a rule\r\n domain(\r\n 'example.test'\r\n ) -> direct\r\n fallback: direct\r\n}\r\n";
        let second = "routing {\n ignored\n dport(443) -> block\n fallback: block\n}\n";
        let loaded = parse_dae_sources(
            &[
                (PathBuf::from("main.dae"), Arc::from(first)),
                (PathBuf::from("child.dae"), Arc::from(second)),
            ],
            SourceLimits::default(),
            &mut Vec::new(),
        )
        .unwrap();
        let index = source_indices(&loaded.sources).unwrap().1;
        assert_eq!(index.rules.len(), loaded.config.routing.rules.len());
        assert_eq!((index.rules[0].source_index, index.rules[0].line), (0, 3));
        assert_eq!(
            &first[index.rules[0].bytes.clone()],
            "domain(\r\n 'example.test'\r\n ) -> direct"
        );
        assert_eq!((index.rules[1].source_index, index.rules[1].line), (1, 3));
        assert_eq!(index.fallback.unwrap().source_index, 1);
    }
}
