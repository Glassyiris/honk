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
                    additions.push_str(newline);
                    additions.push_str(indent);
                    additions.push_str("    ");
                    additions.push_str(field.key());
                    additions.push_str(": ");
                    additions.push_str(&encoded);
                }
            }
            None => {
                for (text, _) in fields {
                    edits.push((text.span.start..text.span.end, String::new()));
                }
            }
        }
    }
    if !additions.is_empty() {
        let close = group.span().end - 1;
        additions.push_str(newline);
        additions.push_str(indent);
        edits.push((close..close, additions));
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSourceLocation {
    pub source_index: usize,
    pub bytes: Range<usize>,
    pub line: usize,
    pub column: usize,
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
    super::routing::parse_section_indexed(&sections, &mut diagnostics, |ordinal, span| {
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
            ],
        )
        .unwrap();
        assert_eq!(
            edited,
            child
                .replace("\"urltest\"", "\"selector\"")
                .replace("tolerance: 4", "")
                .replace("tolerance: 9", "")
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
