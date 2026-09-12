mod diagnostics;
mod dns;
mod routing;

mod structure;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use self::diagnostics::ParserDiagnostics;
use crate::config::GlobalConfig;
use crate::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SafeValue, SettingPath, finish_attempt,
    report_detailed_diagnostics,
};
use crate::error::DetailedConfigError;
use crate::experimental::ExperimentalConfig;
use crate::group::Group;
use crate::node::Node;
use crate::subscription::Subscription;
use crate::{Config, ConfigDiagnostic};
use regex::Regex;
use structure::{Block, Item, quoted_end, scan};
enum ParseFailure {
    Legacy(crate::ConfigError),
    Detailed(crate::error::DetailedConfigError),
}

impl From<crate::ConfigError> for ParseFailure {
    fn from(error: crate::ConfigError) -> Self {
        Self::Legacy(error)
    }
}

impl From<crate::error::DetailedConfigError> for ParseFailure {
    fn from(error: crate::error::DetailedConfigError) -> Self {
        Self::Detailed(error)
    }
}

/// Load a dae configuration file, resolving its top-level `include` blocks.
///
/// Include paths are relative to the entry configuration's directory, even
/// when they occur in a nested included file.  Included files must remain
/// below that directory after symlink resolution.
pub fn parse_dae_config_file(path: impl AsRef<Path>) -> Result<Config, crate::ConfigError> {
    let mut diagnostics = Vec::new();
    let result = parse_dae_config_file_with_detailed_diagnostics(path, &mut diagnostics);
    report_detailed_diagnostics(&diagnostics);
    result.map_err(DetailedConfigError::into_legacy)
}

/// One-release data projection; the caller's existing prefix is preserved.
pub fn parse_dae_config_file_with_diagnostics(
    path: impl AsRef<Path>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Result<Config, crate::ConfigError> {
    let mut detailed = Vec::new();
    let result = parse_dae_config_file_with_detailed_diagnostics(path, &mut detailed);
    diagnostics.extend(detailed.iter().map(DetailedDiagnostic::to_legacy));
    result.map_err(DetailedConfigError::into_legacy)
}

pub fn parse_dae_config_file_with_detailed_diagnostics(
    path: impl AsRef<Path>,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Config, DetailedConfigError> {
    let result = parse_dae_config_file_attempt(path, diagnostics, &mut false);
    finish_attempt(result, diagnostics)
}

pub(crate) fn parse_dae_config_file_attempt(
    path: impl AsRef<Path>,
    diagnostics: &mut Vec<DetailedDiagnostic>,
    semantic: &mut bool,
) -> Result<Config, DetailedConfigError> {
    let source = DiagnosticSources::new(Some(path.as_ref().to_path_buf())).root();
    let mut sink = ParserDiagnostics::new(diagnostics, source);
    match parse_dae_file_inner(path, &mut sink, semantic) {
        Ok(config) => Ok(config),
        Err(ParseFailure::Detailed(error)) => Err(error),
        Err(ParseFailure::Legacy(error)) => Err(sink.error(error)),
    }
}

fn parse_dae_file_inner(
    path: impl AsRef<Path>,
    diagnostics: &mut ParserDiagnostics<'_>,
    semantic: &mut bool,
) -> Result<Config, ParseFailure> {
    let entry =
        std::fs::canonicalize(path.as_ref()).map_err(|error| ParseFailure::Legacy(error.into()))?;
    let entry_dir = entry.parent().map(Path::to_path_buf).ok_or_else(|| {
        ParseFailure::Legacy(crate::ConfigError::Include(format!(
            "entry configuration '{}' has no parent directory",
            entry.display()
        )))
    })?;
    let mut loader = IncludeLoader {
        entry_dir,
        loaded: HashSet::new(),
        stack: Vec::new(),
        saw_include: false,
        entry_input: String::new(),
    };
    let blocks = match loader.expand_file(&entry, diagnostics) {
        Ok(blocks) => blocks,
        Err(err @ crate::ConfigError::Include(_)) => return Err(ParseFailure::Legacy(err)),
        Err(err) if loader.saw_include => {
            return Err(ParseFailure::Legacy(crate::ConfigError::Include(format!(
                "failed to parse configuration after resolving includes: {err}"
            ))));
        }
        Err(err) => return Err(ParseFailure::Legacy(err)),
    };
    match parse_blocks(blocks, diagnostics) {
        Ok(config) => Ok(config),
        Err(err) => {
            *semantic = loader.saw_include || !is_structured_document(&loader.entry_input);
            match err {
                ParseFailure::Detailed(mut error) if loader.saw_include => {
                    if error.category != crate::error::ErrorCategory::UnsupportedPolicy {
                        error.category = crate::error::ErrorCategory::Include;
                    }
                    Err(ParseFailure::Detailed(error))
                }
                err @ ParseFailure::Detailed(_) => Err(err),
                ParseFailure::Legacy(error) if loader.saw_include => {
                    let mut error = diagnostics.error(error);
                    if error.category != crate::error::ErrorCategory::UnsupportedPolicy {
                        error.category = crate::error::ErrorCategory::Include;
                    }
                    Err(ParseFailure::Detailed(error))
                }
                err => Err(err),
            }
        }
    }
}

fn is_structured_document(input: &str) -> bool {
    // A dae semantic failure is final unless the complete document decodes as
    // a YAML, TOML or JSON mapping containing at least one known Config root.
    use crate::config::CONFIG_FIELDS;

    serde_yaml::from_str::<serde_yaml::Value>(input).is_ok_and(|value| {
        value.as_mapping().is_some_and(|mapping| {
            mapping
                .keys()
                .any(|key| key.as_str().is_some_and(|key| CONFIG_FIELDS.contains(&key)))
        })
    }) || toml::from_str::<toml::Value>(input).is_ok_and(|value| {
        value.as_table().is_some_and(|mapping| {
            mapping
                .keys()
                .any(|key| CONFIG_FIELDS.contains(&key.as_str()))
        })
    }) || serde_json::from_str::<serde_json::Value>(input).is_ok_and(|value| {
        value.as_object().is_some_and(|mapping| {
            mapping
                .keys()
                .any(|key| CONFIG_FIELDS.contains(&key.as_str()))
        })
    })
}

struct IncludeLoader {
    entry_dir: PathBuf,
    // dae treats a repeated include as a circular include too.  Keep that
    // behavior, but canonical paths also prevent symlink aliases escaping it.
    loaded: HashSet<PathBuf>,
    stack: Vec<PathBuf>,
    saw_include: bool,
    entry_input: String,
}

impl IncludeLoader {
    fn expand_file(
        &mut self,
        path: &Path,
        diagnostics: &mut ParserDiagnostics<'_>,
    ) -> Result<Vec<Block>, crate::ConfigError> {
        if !self.loaded.insert(path.to_path_buf()) {
            let mut chain = self
                .stack
                .iter()
                .map(|entry| entry.display().to_string())
                .collect::<Vec<_>>();
            chain.push(path.display().to_string());
            return Err(crate::ConfigError::Include(format!(
                "circular or duplicate include is not allowed: {}",
                chain.join(" -> ")
            )));
        }

        let parent = diagnostics.source();
        let source = if self.stack.is_empty() {
            parent
        } else {
            parent
                .sources()
                .add(Some(path.to_path_buf()), Some(parent.index()))
        };
        diagnostics.set_source(source.clone());
        self.stack.push(path.to_path_buf());
        let result = (|| {
            let input = std::fs::read_to_string(path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to read configuration '{}': {err}",
                    path.display()
                ))
            })?;
            let mut structural_diagnostics = Vec::new();
            let roots = scan(
                &input,
                Some(path),
                &mut structural_diagnostics,
                &mut self.saw_include,
            );
            if self.stack.len() == 1 && !matches!(&roots, Err(crate::ConfigError::Include(_))) {
                check_dae_input(&input)?;
            }
            diagnostics.extend(structural_diagnostics);
            let roots = roots?;
            diagnostics.register_blocks(&roots, &source);
            if self.stack.len() == 1 {
                self.entry_input = input;
            }
            let mut blocks = Vec::new();
            let mut patterns = Vec::new();
            for block in roots {
                if block.name == "include" {
                    self.saw_include = true;
                    if let Some(body) = block.include_body.as_deref() {
                        patterns.extend(parse_include_body(body, path)?);
                    }
                } else {
                    blocks.push(block);
                }
            }

            // dae merges an entry's own sections before the sections of its
            // included descendants, regardless of where `include` occurs in
            // that entry.  Appending recursively gives that preorder.
            for pattern in patterns {
                diagnostics.set_source(source.clone());
                for child in self.expand_pattern(&pattern, path)? {
                    diagnostics.set_source(source.clone());
                    blocks.extend(self.expand_file(&child, diagnostics)?);
                }
            }
            Ok(blocks)
        })();
        self.stack.pop();
        result
    }

    fn expand_pattern(
        &self,
        pattern: &str,
        source: &Path,
    ) -> Result<Vec<PathBuf>, crate::ConfigError> {
        let pattern_path = Path::new(pattern);
        let pattern = if pattern_path.is_absolute() {
            pattern_path.to_path_buf()
        } else {
            self.entry_dir.join(pattern_path)
        };
        // `glob` gives `**` recursive semantics while dae's filepath.Glob
        // treats it as an ordinary same-component wildcard.  Normalize the
        // one divergent form before matching.
        let pattern = normalize_dae_glob_pattern(&pattern);
        let pattern_display = pattern.display().to_string();
        let mut matches = glob::glob(&pattern_display)
            .map_err(|err| {
                crate::ConfigError::Include(format!(
                    "invalid include pattern '{}' in '{}': {err}",
                    pattern_display,
                    source.display()
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to expand include pattern '{}' in '{}': {err}",
                    pattern_display,
                    source.display()
                ))
            })?;
        matches.sort();

        let mut files = Vec::new();
        for path in matches {
            if path.extension().and_then(|ext| ext.to_str()) != Some("dae") {
                continue;
            }
            let metadata = std::fs::metadata(&path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to inspect included path '{}': {err}",
                    path.display()
                ))
            })?;
            if metadata.is_dir() {
                continue;
            }

            let path = std::fs::canonicalize(&path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to resolve included path '{}': {err}",
                    path.display()
                ))
            })?;
            if !path.starts_with(&self.entry_dir) {
                return Err(crate::ConfigError::Include(format!(
                    "included path '{}' is outside entry configuration directory '{}'",
                    path.display(),
                    self.entry_dir.display()
                )));
            }
            files.push(path);
        }
        Ok(files)
    }
}

fn normalize_dae_glob_pattern(pattern: &Path) -> PathBuf {
    // honk runs on Linux, where `/` is both the dae and native separator.
    let normalized = pattern
        .to_string_lossy()
        .split('/')
        .map(|component| if component == "**" { "*" } else { component })
        .collect::<Vec<_>>()
        .join("/");
    PathBuf::from(normalized)
}

fn parse_include_body(body: &str, source: &Path) -> Result<Vec<String>, crate::ConfigError> {
    let bytes = body.as_bytes();
    let mut index = 0;
    let mut patterns = Vec::new();

    while index < bytes.len() {
        loop {
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if index < bytes.len() && bytes[index] == b'#' {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            } else {
                break;
            }
        }
        if index >= bytes.len() {
            break;
        }
        if matches!(bytes[index], b'{' | b'}') {
            return Err(crate::ConfigError::Include(format!(
                "include section in '{}' accepts only file patterns",
                source.display()
            )));
        }

        let value = if matches!(bytes[index], b'\'' | b'"') {
            let start = index + 1;
            let end = quoted_end(bytes, index).ok_or_else(|| {
                crate::ConfigError::Include(format!(
                    "unterminated quoted include path in '{}'",
                    source.display()
                ))
            })?;
            index = end;
            body[start..end - 1].to_string()
        } else {
            let start = index;
            while index < bytes.len()
                && !bytes[index].is_ascii_whitespace()
                && bytes[index] != b'#'
                && !matches!(bytes[index], b'{' | b'}')
            {
                index += 1;
            }
            body[start..index].to_string()
        };
        if value.is_empty() {
            return Err(crate::ConfigError::Include(format!(
                "empty include path in '{}'",
                source.display()
            )));
        }
        patterns.push(value);
    }

    Ok(patterns)
}

pub fn parse_dae_config(input: &str) -> Result<Config, crate::ConfigError> {
    let mut diagnostics = Vec::new();
    let result = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics);
    report_detailed_diagnostics(&diagnostics);
    result.map_err(DetailedConfigError::into_legacy)
}

/// One-release data projection; never logs or exposes arbitrary input values.
pub fn parse_dae_config_with_diagnostics(
    input: &str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Result<Config, crate::ConfigError> {
    let mut detailed = Vec::new();
    let result = parse_dae_config_with_detailed_diagnostics(input, &mut detailed);
    diagnostics.extend(detailed.iter().map(DetailedDiagnostic::to_legacy));
    result.map_err(DetailedConfigError::into_legacy)
}

pub fn parse_dae_config_with_detailed_diagnostics(
    input: &str,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> Result<Config, DetailedConfigError> {
    let source = DiagnosticSources::new(None).root();
    let mut sink = ParserDiagnostics::new(diagnostics, source.clone());
    let result: Result<Config, ParseFailure> = (|| {
        check_dae_input(input)?;
        let mut structural = Vec::new();
        let blocks = scan(input, None, &mut structural, &mut false);
        sink.extend(structural);
        let blocks = blocks?;
        sink.register_blocks(&blocks, &source);
        parse_blocks(blocks, &mut sink)
    })();
    let result = result.map_err(|error| match error {
        ParseFailure::Detailed(error) => error,
        ParseFailure::Legacy(error) => sink.error(error),
    });
    finish_attempt(result, sink.output)
}

fn check_dae_input(input: &str) -> Result<(), crate::ConfigError> {
    let mut has_open = false;
    let mut has_close = false;
    for line in input.lines().map(str::trim_start) {
        if !line.starts_with('#') {
            has_open |= line.contains('{');
            has_close |= line.contains('}');
        }
    }
    if !has_open || !has_close {
        return Err(crate::ConfigError::Parse("not a dae config file".into()));
    }
    Ok(())
}

fn parse_blocks(
    blocks: Vec<Block>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Config, ParseFailure> {
    let mut sections = Vec::<Block>::new();
    let mut indices = HashMap::<String, usize>::new();
    for block in blocks {
        if let Some(&index) = indices.get(&block.name) {
            sections[index].items.extend(block.items);
        } else {
            indices.insert(block.name.clone(), sections.len());
            sections.push(block);
        }
    }

    let canonical_nfqueue_present = sections
        .iter()
        .filter(|section| section.name == "global")
        .any(|section| parse_kv_pairs(section.lines_except(&[])).contains_key("nfqueue_enable"));
    let mut config = Config::default();

    for section in &sections {
        diagnostics.at_section(section, &[]);
        match section.name.as_str() {
            "global" => config.global = parse_global_section(section, diagnostics)?,
            "dns" => config.dns = dns::parse_section(section, diagnostics)?,
            "routing" => config.routing = routing::parse_section(section, diagnostics)?,
            "node" => {
                for node in parse_node_section(section, diagnostics)? {
                    config.nodes.push(node);
                }
            }
            "group" => {
                for group in parse_group_section(section, diagnostics)? {
                    config.groups.push(group);
                }
            }
            "subscription" => {
                for sub in parse_subscription_section(section, diagnostics)? {
                    config.subscriptions.push(sub);
                }
            }
            "experimental" => {
                config.experimental = parse_experimental_section(section, diagnostics)?;
            }
            _ => {}
        }
    }
    config.apply_legacy_nfqueue(canonical_nfqueue_present);

    for group in &mut config.groups {
        if group.policy == crate::node::GroupPolicy::URLTest {
            group.tolerance = config.global.check_tolerance_ms;
        }
    }

    resolve_group_filters_inner(
        &mut config.groups,
        &config.nodes,
        &config.subscriptions,
        Some(diagnostics),
    );

    Ok(config)
}

/// Resolve group filters into concrete node UUIDs.
///
/// Each `filter:` line is OR-ed. Predicates joined by `&&` within one line
/// are AND-ed and may be negated with `!`. Supported predicates are
/// `name(...)` and dae-compatible `subtag(...)`; both accept exact values,
/// `keyword:`, and `regex:` arguments.
///
/// `group('tag')` entries are not node filters — the dae parser routes them
/// into `Group.groups` at parse time.
pub fn resolve_group_filters(groups: &mut [Group], nodes: &[Node], subscriptions: &[Subscription]) {
    // Runtime re-resolution: the filters were reported when the config was parsed.
    resolve_group_filters_inner(groups, nodes, subscriptions, None);
}

fn resolve_group_filters_inner(
    groups: &mut [Group],
    nodes: &[Node],
    subscriptions: &[Subscription],
    mut diagnostics: Option<&mut ParserDiagnostics<'_>>,
) {
    let mut subscription_tags: HashMap<uuid::Uuid, Vec<&str>> = HashMap::new();
    for subscription in subscriptions {
        subscription_tags
            .entry(subscription.id)
            .or_default()
            .push(subscription.name.as_str());
    }

    for (group_index, group) in groups.iter_mut().enumerate() {
        if let Some(diagnostics) = diagnostics.as_deref_mut() {
            diagnostics.select_group(group_index + 1);
        }
        let filters: Vec<(usize, &str)> = group
            .filters
            .iter()
            .enumerate()
            .map(|(index, filter)| (index, filter.trim()))
            .filter(|(_, filter)| {
                standalone_group_reference(filter).is_none_or(|args| {
                    split_unquoted(args, ",")
                        .map(unquote_filter_argument)
                        .flat_map(|tag| tag.split(['|', ',']))
                        .all(|tag| tag.trim().is_empty())
                })
            })
            .collect();

        if filters.is_empty() {
            if group.groups.is_empty() {
                for node in nodes {
                    if !group.nodes.contains(&node.id) {
                        group.nodes.push(node.id);
                    }
                }
            }
            continue;
        }

        let mut parsed_filters = Vec::new();
        for (index, filter) in filters {
            if standalone_group_reference(filter).is_some() {
                continue;
            }
            if let Some(parsed) = parse_group_filter_expression(filter) {
                parsed_filters.push(parsed);
            } else if let Some(diagnostics) = diagnostics.as_deref_mut() {
                diagnostics.push(ConfigDiagnostic {
                    setting: format!("group.{}.filter", group.name),
                    value: (index + 1).to_string(),
                    message:
                        if filter.starts_with("group(") && find_unquoted(filter, ")").is_none() {
                            "group(...) is unterminated; ignored"
                        } else if filter.starts_with("group(") {
                            "group(...) must be the whole filter line; ignored"
                        } else {
                            "honk could not parse this filter; ignored"
                        }
                        .to_string(),
                });
            }
        }
        group.nodes.clear();
        for node in nodes {
            if parsed_filters.iter().any(|filter| {
                filter
                    .iter()
                    .all(|term| term.matches(node, &subscription_tags))
            }) && !group.nodes.contains(&node.id)
            {
                group.nodes.push(node.id);
            }
        }
    }
}

struct GroupFilterTerm {
    matcher: GroupFilterMatcher,
    negated: bool,
}

enum GroupFilterMatcher {
    Name(Regex),
    SubscriptionTag(Regex),
}

impl GroupFilterTerm {
    fn matches(&self, node: &Node, subscription_tags: &HashMap<uuid::Uuid, Vec<&str>>) -> bool {
        let matched = match &self.matcher {
            GroupFilterMatcher::Name(pattern) => pattern.is_match(&node.name),
            GroupFilterMatcher::SubscriptionTag(pattern) => node
                .subscription_id
                .and_then(|id| subscription_tags.get(&id))
                .is_some_and(|tags| tags.iter().any(|tag| pattern.is_match(tag))),
        };
        if self.negated { !matched } else { matched }
    }
}

fn parse_group_filter_expression(filter: &str) -> Option<Vec<GroupFilterTerm>> {
    let mut terms = Vec::new();
    for raw_term in split_unquoted(filter, "&&") {
        let raw_term = raw_term.trim();
        let (negated, predicate) = match raw_term.strip_prefix('!') {
            Some(predicate) => (true, predicate.trim()),
            None => (false, raw_term),
        };
        let matcher = if predicate.starts_with("name(") {
            GroupFilterMatcher::Name(parse_text_filter(predicate, "name")?)
        } else if predicate.starts_with("subtag(") {
            GroupFilterMatcher::SubscriptionTag(parse_text_filter(predicate, "subtag")?)
        } else {
            return None;
        };
        terms.push(GroupFilterTerm { matcher, negated });
    }
    (!terms.is_empty()).then_some(terms)
}

fn parse_text_filter(filter: &str, function: &str) -> Option<Regex> {
    let body = filter
        .strip_prefix(function)?
        .strip_prefix('(')?
        .strip_suffix(')')?
        .trim();
    let mut patterns = Vec::new();
    for argument in split_filter_arguments(body)? {
        let argument = argument.trim();
        let pattern = if let Some(value) = argument.strip_prefix("keyword:") {
            let value = unquote_filter_argument(value);
            if value.is_empty() {
                continue;
            }
            regex::escape(value)
        } else if let Some(value) = argument.strip_prefix("regex:") {
            let value = unquote_filter_argument(value);
            if value.is_empty() {
                continue;
            }
            format!("(?:{value})")
        } else {
            let value = unquote_filter_argument(argument);
            if value.is_empty() {
                continue;
            }
            format!("^(?:{})$", regex::escape(value))
        };
        patterns.push(pattern);
    }
    if patterns.is_empty() {
        return None;
    }
    Regex::new(&patterns.join("|")).ok()
}

fn split_filter_arguments(body: &str) -> Option<Vec<&str>> {
    let bytes = body.as_bytes();
    let mut arguments = Vec::new();
    let mut start = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b',' => {
                arguments.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if quote.is_some() {
        return None;
    }
    arguments.push(&body[start..]);
    Some(arguments)
}

fn unquote_filter_argument(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes[0], bytes[value.len() - 1]),
            (b'\'', b'\'') | (b'"', b'"')
        ) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn split_entry_tag(mut line: &str) -> (Option<&str>, &str) {
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                if let Some(end) = quoted_end(bytes, index) {
                    index = end;
                    continue;
                }
            }
            b'#' if index == 0 || matches!(bytes[index - 1], b' ' | b'\t') => {
                line = line[..index].trim_end();
                break;
            }
            _ => {}
        }
        index += 1;
    }

    if line.starts_with(['\'', '"']) {
        if let Some(end) = quoted_end(line.as_bytes(), 0)
            && let Some(value) = line[end..].trim_start().strip_prefix(':')
        {
            return (Some(&line[..end]), value.trim());
        }
    } else if let Some(pos) = line.find(':')
        && !line[pos..].starts_with("://")
    {
        return (Some(&line[..pos]), line[pos + 1..].trim());
    }
    (None, line)
}

fn parse_kv_pair(line: &str) -> Option<(&str, &str)> {
    let trimmed = strip_unquoted_comment(line.trim()).trim();
    let (key, value) = trimmed.split_once(':')?;
    Some((
        key.trim(),
        value.trim().trim_matches('\'').trim_matches('"'),
    ))
}

fn parse_kv_pairs<'a>(lines: impl IntoIterator<Item = &'a str>) -> HashMap<String, String> {
    lines
        .into_iter()
        .filter_map(parse_kv_pair)
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn strip_unquoted_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == '#' {
            return &line[..index];
        }
    }
    line
}
fn parse_global_section(
    section: &Block,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<GlobalConfig, ParseFailure> {
    let mut cfg = GlobalConfig::default();
    let kv = parse_kv_pairs(section.lines_except(&[]));

    if let Some(v) = kv.get("tproxy_port") {
        cfg.tproxy_port = lenient(v.parse().ok(), 12345, diagnostics, || ConfigDiagnostic {
            setting: "global.tproxy_port".to_string(),
            value: v.clone(),
            message: "honk could not parse this port as a decimal in 0-65535; using fallback 12345"
                .to_string(),
        });
    }
    if let Some(v) = kv.get("tproxy_port_protect") {
        cfg.tproxy_port_protect = lenient_bool(v, "global.tproxy_port_protect", diagnostics);
    }
    if let Some(v) = kv.get("pprof_port") {
        cfg.pprof_port = lenient(v.parse().ok(), 0, diagnostics, || ConfigDiagnostic {
            setting: "global.pprof_port".to_string(),
            value: v.clone(),
            message: "honk could not parse this port as a decimal in 0-65535; using fallback 0"
                .to_string(),
        });
    }
    if let Some(v) = kv.get("so_mark_from_dae") {
        cfg.so_mark_from_dae = lenient(parse_hex_or_dec(v), 0, diagnostics, || ConfigDiagnostic {
            setting: "global.so_mark_from_dae".to_string(),
            value: v.clone(),
            message: "honk could not parse this mark as a u32; using fallback 0".to_string(),
        });
    }
    if let Some(v) = kv.get("log_level") {
        cfg.log_level = v.clone();
    }
    if let Some(v) = kv.get("log_file") {
        cfg.log_file = v.clone();
    }
    if let Some(v) = kv.get("disable_waiting_network") {
        cfg.disable_waiting_network =
            lenient_bool(v, "global.disable_waiting_network", diagnostics);
    }
    if let Some(v) = kv.get("lan_interface") {
        cfg.lan_interface = v
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect();
    }
    if let Some(v) = kv.get("wan_interface") {
        cfg.wan_interface = v
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect();
    }
    if let Some(v) = kv.get("auto_config_kernel_parameter") {
        cfg.auto_config_kernel_parameter =
            lenient_bool(v, "global.auto_config_kernel_parameter", diagnostics);
    }
    if let Some(v) = kv.get("data_dir") {
        cfg.data_dir = v.clone();
    }
    if let Some(v) = kv.get("store_subscribe") {
        cfg.store_subscribe = lenient_bool(v, "global.store_subscribe", diagnostics);
    }
    if let Some(v) = kv.get("tcp_check_url") {
        cfg.tcp_check_url = v
            .split(',')
            .map(|s| s.trim().trim_matches('\'').to_string())
            .collect();
    }
    if let Some(v) = kv.get("tcp_check_http_method") {
        cfg.tcp_check_http_method = v.clone();
    }
    if let Some(v) = kv.get("udp_check_dns") {
        cfg.udp_check_dns = v
            .split(',')
            .map(|s| s.trim().trim_matches('\'').to_string())
            .collect();
    }
    if let Some(v) = kv.get("check_interval") {
        cfg.check_interval_secs =
            lenient(crate::types::parse_duration_secs(v), 0, diagnostics, || {
                ConfigDiagnostic {
                    setting: "global.check_interval".to_string(),
                    value: v.clone(),
                    message: "duration is unsupported by honk; using fallback 0s".to_string(),
                }
            });
    }
    if let Some(v) = kv.get("check_tolerance") {
        cfg.check_tolerance_ms = lenient_duration_ms(
            v,
            "global.check_tolerance",
            cfg.check_tolerance_ms,
            diagnostics,
        );
    }
    if let Some(v) = kv.get("dial_mode") {
        cfg.dial_mode = v.clone();
    }
    if let Some(v) = kv.get("nfqueue_enable") {
        cfg.nfqueue_enable = parse_checked_bool(v, "global.nfqueue_enable").map_err(|_| {
            let (source, line) = diagnostics.field_location("nfqueue_enable");
            let mut error = DetailedConfigError::new(
                crate::error::ErrorCategory::Parse,
                "invalid-config-value",
                source,
                SettingPath::new("global").field("nfqueue_enable"),
                "expected true/false, yes/no, 1/0 or on/off",
            );
            error.diagnostic.line = line;
            ParseFailure::Detailed(error)
        })?;
    }
    if let Some(v) = kv.get("allow_insecure") {
        cfg.allow_insecure = lenient_bool(v, "global.allow_insecure", diagnostics);
    }
    if let Some(v) = kv.get("sniffing_timeout") {
        cfg.sniffing_timeout_ms = lenient_duration_ms(
            v,
            "global.sniffing_timeout",
            cfg.sniffing_timeout_ms,
            diagnostics,
        );
    }
    if let Some(v) = kv.get("tls_implementation") {
        cfg.tls_implementation = v.clone();
    }
    if let Some(v) = kv.get("utls_imitate") {
        cfg.utls_imitate = v.clone();
    }
    if let Some(v) = kv.get("tls_fragment") {
        cfg.tls_fragment = lenient_bool(v, "global.tls_fragment", diagnostics);
    }
    if let Some(v) = kv.get("tls_fragment_length") {
        cfg.tls_fragment_length = v.clone();
    }
    if let Some(v) = kv.get("tls_fragment_interval") {
        cfg.tls_fragment_interval = v.clone();
    }
    if let Some(v) = kv.get("mptcp") {
        cfg.mptcp = lenient_bool(v, "global.mptcp", diagnostics);
    }
    if let Some(v) = kv.get("bootstrap_resolver") {
        cfg.bootstrap_resolver = v.clone();
    }
    if let Some(v) = kv.get("fallback_resolver") {
        cfg.fallback_resolver = v.clone();
    }
    if let Some(v) = kv.get("bandwidth_max_tx") {
        cfg.bandwidth_max_tx = v.clone();
    }
    if let Some(v) = kv.get("bandwidth_max_rx") {
        cfg.bandwidth_max_rx = v.clone();
    }
    if let Some(v) = kv.get("udp_warm_node_count") {
        cfg.udp_warm_node_count = v
            .parse()
            .map_err(|_| crate::ConfigError::Parse(format!("invalid udp_warm_node_count: {v}")))?;
    }
    if let Some(v) = kv.get("preconnect_node_count") {
        let trimmed = v.trim().trim_matches('\'');
        cfg.preconnect_node_count = if trimmed.eq_ignore_ascii_case("auto") {
            crate::config::PRECONNECT_NODE_COUNT_AUTO
        } else {
            trimmed.parse().map_err(|_| {
                crate::ConfigError::Parse(format!("invalid preconnect_node_count: {v}"))
            })?
        };
    }
    if let Some(v) = kv.get("max_concurrent_dials") {
        cfg.max_concurrent_dials = v
            .parse()
            .map_err(|_| crate::ConfigError::Parse(format!("invalid max_concurrent_dials: {v}")))?;
    }

    crate::check::validate_dns_check_targets(&cfg.udp_check_dns).map_err(|mut error| {
        let (source, line) = diagnostics.field_location("udp_check_dns");
        error.diagnostic.source = source;
        if error.diagnostic.line.is_none() {
            error.diagnostic.line = line;
        }
        ParseFailure::Detailed(error)
    })?;
    Ok(cfg)
}

fn find_unquoted(input: &str, delimiter: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            index = quoted_end(bytes, index)?;
        } else if bytes[index..].starts_with(delimiter.as_bytes()) {
            return Some(index);
        } else {
            index += 1;
        }
    }
    None
}

fn split_unquoted<'a>(input: &'a str, delimiter: &'a str) -> impl Iterator<Item = &'a str> {
    let mut remaining = Some(input);
    std::iter::from_fn(move || {
        let input = remaining.take()?;
        if let Some(index) = find_unquoted(input, delimiter) {
            remaining = Some(&input[index + delimiter.len()..]);
            Some(&input[..index])
        } else {
            Some(input)
        }
    })
}

/// Returns the raw argument text of a standalone `group(...)` filter line.
fn standalone_group_reference(val: &str) -> Option<&str> {
    let body = strip_unquoted_comment(val.trim().strip_prefix("group(")?);
    let end = find_unquoted(body, ")")?;
    let args = &body[..end];
    (body[end + 1..].trim().is_empty() && find_unquoted(args, "(").is_none()).then_some(args)
}

fn extract_fn_args(expr: &str, fn_name: &str) -> Option<Vec<String>> {
    let body = expr.strip_prefix(fn_name)?.strip_prefix('(')?;
    let end = find_unquoted(body, ")")?;
    if !body[end + 1..].trim().is_empty() {
        return None;
    }
    let args = &body[..end];
    Some(
        split_unquoted(args, ",")
            .map(unquote_filter_argument)
            .filter(|arg| !arg.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// Strip a `prefix:` marker from a route argument.  Dae syntax allows spaces
/// after the colon (`geosite: cn`), and the value may carry its own quotes.
fn strip_tag_arg(arg: &str, prefix: &str) -> Option<String> {
    arg.strip_prefix(prefix)
        .map(|value| unquote_filter_argument(value).to_string())
}

/// Normalize a geosite list name.
fn normalize_geosite_code(code: &str) -> String {
    // Keep the code verbatim: `@attr` is an attribute filter applied at
    // expansion time (honk-core routing/geo.rs), not part of the category
    // name — remapping it to `-` silently mismatched into a nonexistent
    // category.
    code.trim().to_string()
}

fn parse_node_section(
    section: &Block,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Vec<Node>, ParseFailure> {
    let mut nodes = Vec::new();
    let lines = section.lines_except(&[]);
    for (index, line) in lines.into_iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        diagnostics.entry(line, index + 1);
        if let Some(rest) = trimmed.strip_prefix("mux")
            && rest.trim_start().starts_with(['=', ':'])
        {
            let (source, line) = diagnostics.field_location("mux");
            let mut error = DetailedConfigError::new(
                crate::error::ErrorCategory::Parse,
                "unsupported-node-mux",
                source,
                SettingPath::new("nodes").field("mux"),
                "standalone mux is unsupported; set vless_mode on each VLESS share link",
            );
            error.diagnostic.line = line;
            return Err(error.into());
        }
        let unquote = |s: &str| s.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
        let (tag, value) = split_entry_tag(trimmed);
        let (tag, uri) = match tag {
            Some(tag) if tag.starts_with(['\'', '"']) => {
                (tag[1..tag.len() - 1].to_string(), unquote(value))
            }
            Some(tag) if tag.contains(char::is_whitespace) => (String::new(), trimmed.to_string()),
            Some(tag) => (unquote(tag), unquote(value)),
            None if value.starts_with(['\'', '"']) => (
                String::new(),
                quoted_end(value.as_bytes(), 0)
                    .map(|end| value[1..end - 1].to_string())
                    .unwrap_or_else(|| unquote(value)),
            ),
            None if value.contains(':') => (String::new(), value.to_string()),
            None => (String::new(), unquote(value)),
        };
        match diagnostics.parse_share_link(&uri) {
            Ok(mut node) => {
                if !tag.is_empty() {
                    node.name = tag;
                }
                nodes.push(node);
            }
            // Config documents reject removed protocols; subscriptions skip them.
            Err(error) if error.category == crate::error::ErrorCategory::UnknownProtocol => {
                return Err(ParseFailure::Detailed(error));
            }
            Err(_) => diagnostics.emit(DetailedDiagnostic::warning(
                "invalid-node-entry",
                diagnostics.source(),
                SettingPath::new("nodes").index(index + 1),
                SafeValue::Redacted,
                "node entry could not be parsed; ignored",
            )),
        }
    }
    Ok(nodes)
}
fn parse_group_section(
    section: &Block,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Vec<Group>, crate::ConfigError> {
    let mut groups = Vec::new();

    for grp in section.blocks_any() {
        diagnostics.begin_group(grp, groups.len() + 1);
        let mut group = Group {
            name: grp.name.clone(),
            ..Default::default()
        };
        let lines = grp.lines_except(&[]);
        let kv = parse_kv_pairs(lines.iter().copied());
        if let Some(policy) = kv.get("policy") {
            group.policy = parse_group_policy(policy, &group.name, diagnostics)?;
        }
        if let Some(final_outbound) = kv.get("final") {
            group.final_outbound = Some(final_outbound.to_string());
        }
        // sing-box SelectorOutboundOptions.Default: explicit initial member.
        if let Some(default) = kv.get("default") {
            group.default = Some(default.trim_matches(|c| c == '\'' || c == '"').to_string());
        }
        // sing-box URLTestOutboundOptions.URL: per-group health check target
        // (overrides global tcp_check_url for this group's URLTest selection).
        if let Some(check_url) = kv.get("check_url") {
            group.check_url = Some(
                check_url
                    .trim_matches(|c| c == '\'' || c == '"')
                    .to_string(),
            );
        }

        let filter_lines = lines
            .iter()
            .copied()
            .filter(|line| line.trim().starts_with("filter:"));
        for line in filter_lines {
            let val = line
                .split_once(':')
                .map(|(_, v)| strip_unquoted_comment(v.trim()).trim())
                .unwrap_or("");
            if let Some(args) = standalone_group_reference(val) {
                let mut has_tag = false;
                for tag in split_unquoted(args, ",")
                    .map(unquote_filter_argument)
                    .flat_map(|tag| tag.split(['|', ',']).map(str::trim))
                    .map(str::to_string)
                {
                    has_tag |= !tag.is_empty();
                    if !tag.is_empty() && !group.groups.contains(&tag) {
                        group.groups.push(tag);
                    }
                }
                if !has_tag {
                    diagnostics.remember_filter(line);
                    diagnostics.at_line(line);
                    group.filters.push(val.to_string());
                    diagnostics.emit(DetailedDiagnostic::warning(
                        "empty-subgroup",
                        diagnostics.source(),
                        SettingPath::new("groups").index(groups.len() + 1).field("filter").index(group.filters.len()),
                        SafeValue::Ordinal(group.filters.len()),
                        "empty subgroup contribution selects no nodes; remove the filter to select all nodes",
                    ));
                }
            } else {
                diagnostics.remember_filter(line);
                group.filters.push(val.to_string());
            }
        }

        groups.push(group);
    }

    Ok(groups)
}

fn parse_group_policy(
    policy: &str,
    group_name: &str,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<crate::group::GroupPolicy, crate::ConfigError> {
    let base = policy
        .trim()
        .split_once('(')
        .map(|(name, _)| name.trim())
        .unwrap_or_else(|| policy.trim())
        .to_ascii_lowercase();
    match base.as_str() {
        "select" | "selector" | "fixed" => Ok(crate::group::GroupPolicy::Selector),
        "urltest" | "min_moving_avg" | "min_avg10" | "min_last_delay" => {
            Ok(crate::group::GroupPolicy::URLTest)
        }
        "roundrobin" | "round_robin" | "loadbalance" | "balance" => {
            Ok(crate::group::GroupPolicy::LoadBalance)
        }
        "fallback" => Ok(crate::group::GroupPolicy::Fallback),
        "score" => Ok(crate::group::GroupPolicy::Score),
        "honk" => Err(crate::ConfigError::UnsupportedPolicy(
            "group policy 'honk' was renamed to 'score'".into(),
        )),
        _ => {
            diagnostics.push(ConfigDiagnostic {
                setting: format!("group.{group_name}.policy"),
                value: String::new(),
                message: "policy is not recognised; using fallback selector".to_string(),
            });
            Ok(crate::group::GroupPolicy::Selector)
        }
    }
}

fn parse_subscription_section(
    section: &Block,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<Vec<Subscription>, crate::ConfigError> {
    let mut subs = Vec::new();
    append_subscriptions(&section.items, &mut subs, diagnostics);
    Ok(subs)
}

fn append_subscriptions(
    items: &[Item],
    subs: &mut Vec<Subscription>,
    diagnostics: &mut ParserDiagnostics<'_>,
) {
    for item in items {
        match item {
            Item::Statement(line, _) => subs.extend(parse_subscription_entry(line)),
            Item::Block(block) => {
                let Some((tag, _)) = block
                    .header
                    .split_once(':')
                    .filter(|(_, value)| value.trim() == "{")
                else {
                    subs.extend(parse_subscription_entry(&block.header));
                    append_subscriptions(&block.items, subs, diagnostics);
                    subs.extend(parse_subscription_entry(&block.closing));
                    continue;
                };
                let kv = parse_kv_pairs(block.lines_except(&[]));
                diagnostics.subscription(block, subs.len() + 1);
                let mut sub = Subscription {
                    name: unquote_filter_argument(tag).to_string(),
                    ..Default::default()
                };
                if let Some(url) = kv.get("url") {
                    sub.url = url.clone();
                }
                if let Some(ua) = kv.get("ua") {
                    sub.user_agent = Some(ua.clone());
                }
                if let Some(interval) = kv.get("interval") {
                    sub.update_interval = lenient(
                        crate::types::parse_duration_secs(interval),
                        0,
                        diagnostics,
                        || ConfigDiagnostic {
                            setting: format!("subscription.{}.interval", sub.name),
                            value: interval.clone(),
                            message: "duration is unsupported by honk; using fallback 0s"
                                .to_string(),
                        },
                    );
                }
                subs.push(sub);
            }
        }
    }
}

fn parse_subscription_entry(line: &str) -> Option<Subscription> {
    let (tag, value) = split_entry_tag(line.trim());
    let (mut url, user_agent) = parse_subscription_value(value);
    let name = if let Some(tag) = tag {
        unquote_filter_argument(tag).to_string()
    } else {
        let tag_colon = url.find(':').filter(|&pos| !url[pos..].starts_with("://"));
        let value = tag_colon.map_or(url.as_str(), |pos| &url[pos + 1..]);
        if !value.contains("://") {
            return None;
        }
        if let Some(pos) = tag_colon {
            let name = url[..pos].to_string();
            url.drain(..=pos);
            name
        } else {
            url::Url::parse(&url)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
                .unwrap_or_default()
        }
    };
    Some(Subscription {
        name,
        url,
        user_agent,
        ..Default::default()
    })
}

fn parse_subscription_value(value: &str) -> (String, Option<String>) {
    let value = value.trim();
    if matches!(value.as_bytes().first().copied(), Some(b'\'' | b'"'))
        && let Some(end) = quoted_end(value.as_bytes(), 0)
    {
        let mut remainder = value[end..].trim();
        if remainder.is_empty() || remainder.starts_with('#') {
            return (value[1..end - 1].to_string(), None);
        }
        if remainder.starts_with('(') {
            let bytes = remainder.as_bytes();
            let mut depth = 0;
            let mut index = 0;
            while index < bytes.len() {
                match bytes[index] {
                    b'\'' | b'"' => {
                        if let Some(end) = quoted_end(bytes, index) {
                            index = end;
                            continue;
                        }
                    }
                    b'(' => depth += 1,
                    b')' if depth > 0 => {
                        depth -= 1;
                        if depth == 0 && bytes.get(index + 1) == Some(&b'#') {
                            remainder = &remainder[..index + 1];
                            break;
                        }
                    }
                    _ => {}
                }
                index += 1;
            }
        }
        if let Some(ua) = remainder
            .strip_prefix('(')
            .and_then(|ua| ua.strip_suffix(')'))
        {
            return (
                value[1..end - 1].to_string(),
                Some(unquote_filter_argument(ua).to_string()),
            );
        }
    }
    (unquote_filter_argument(value).to_string(), None)
}
fn parse_experimental_section(
    section: &Block,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<ExperimentalConfig, crate::ConfigError> {
    let mut cfg = ExperimentalConfig::default();
    let mut api_location = None;
    let recognised = ["clash_api", "cache_file", "udp_nfqueue"];
    let ambient = section.lines_except(&recognised);
    if let Some(setting) = ambient.into_iter().find(|line| !line.trim().is_empty()) {
        return Err(crate::ConfigError::Parse(format!(
            "unknown experimental setting: {}",
            setting.trim()
        )));
    }
    let subs = section.blocks_matching(&recognised);

    for sub in subs {
        diagnostics.at_section(sub, &[]);
        let kv = parse_kv_pairs(sub.lines_except(&[]));
        match sub.name.as_str() {
            "clash_api" => {
                if let Some(v) = kv.get("external_controller") {
                    cfg.clash_api.external_controller = v.clone();
                    api_location = Some(diagnostics.field_location("external_controller"));
                }
                if let Some(v) = kv.get("external_ui") {
                    cfg.clash_api.external_ui = v.clone();
                }
                if let Some(v) = kv.get("external_ui_download_url") {
                    cfg.clash_api.external_ui_download_url = v.clone();
                }
                if let Some(v) = kv.get("external_ui_download_detour") {
                    cfg.clash_api.external_ui_download_detour = v.clone();
                }
                if let Some(v) = kv.get("secret") {
                    cfg.clash_api.secret = v.clone();
                }
                if let Some(v) = kv.get("default_mode") {
                    cfg.clash_api.default_mode = v.clone();
                }
            }
            "cache_file" => {
                if let Some(v) = kv.get("enabled") {
                    cfg.cache_file.enabled =
                        lenient_bool(v, "experimental.cache_file.enabled", diagnostics);
                }
                if let Some(v) = kv.get("path") {
                    cfg.cache_file.path = v.clone();
                }
                if let Some(v) = kv.get("cache_id") {
                    cfg.cache_file.cache_id = v.clone();
                }
                if let Some(v) = kv.get("store_fakeip") {
                    cfg.cache_file.store_fakeip =
                        lenient_bool(v, "experimental.cache_file.store_fakeip", diagnostics);
                }
                if let Some(v) = kv.get("store_dns") {
                    cfg.cache_file.store_dns =
                        lenient_bool(v, "experimental.cache_file.store_dns", diagnostics);
                }
            }
            "udp_nfqueue" => {
                if let Some(key) = kv.keys().find(|key| key.as_str() != "enabled") {
                    return Err(crate::ConfigError::Parse(format!(
                        "unknown experimental.udp_nfqueue setting: {key}"
                    )));
                }
                let enabled = kv
                    .get("enabled")
                    .map(|value| parse_checked_bool(value, "experimental.udp_nfqueue.enabled"))
                    .transpose()?
                    .unwrap_or(false);
                cfg.legacy_udp_nfqueue =
                    Some(crate::experimental::LegacyUdpNfqueueConfig { enabled });
                diagnostics.emit(crate::diagnostic::legacy_nfqueue_warning(
                    diagnostics.source(),
                ));
            }
            _ => {}
        }
    }
    if let Some((source, line)) = api_location
        && let Some(mut diagnostic) = cfg.clash_api.exposure_diagnostic(source)
    {
        diagnostic.line = line;
        diagnostics.output.push(diagnostic);
    }

    Ok(cfg)
}

fn parse_checked_bool(s: &str, setting: &str) -> Result<bool, crate::ConfigError> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(true),
        "false" | "no" | "0" | "off" => Ok(false),
        _ => Err(crate::ConfigError::Parse(format!(
            "invalid boolean for {setting}: {s}"
        ))),
    }
}

/// Keep `fallback` when `parsed` is `None` and record why. For settings whose
/// unparseable value does not justify rejecting the configuration.
fn lenient<T>(
    parsed: Option<T>,
    fallback: T,
    diagnostics: &mut ParserDiagnostics<'_>,
    diagnostic: impl FnOnce() -> ConfigDiagnostic,
) -> T {
    match parsed {
        Some(value) => value,
        None => {
            diagnostics.push(diagnostic());
            fallback
        }
    }
}

/// Lenient boolean for dae settings honk does not reject. Recognised spellings are dae's
/// (`true/t/1/y/yes/on`, `false/f/0/n/no/off`, case-insensitive) and produce no
/// diagnostic; `t` and `y` still yield false, a divergence recorded in the lab notes.
fn lenient_bool(value: &str, setting: &str, diagnostics: &mut ParserDiagnostics<'_>) -> bool {
    let lowered = value.to_lowercase();
    match lowered.as_str() {
        "true" | "yes" | "1" | "on" => true,
        "false" | "f" | "0" | "n" | "no" | "off" | "t" | "y" => false,
        _ => {
            diagnostics.push(ConfigDiagnostic {
                setting: setting.to_string(),
                value: value.to_string(),
                message: "value is not a boolean spelling honk recognises; using fallback false"
                    .to_string(),
            });
            false
        }
    }
}

fn parse_hex_or_dec(s: &str) -> Option<u32> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).ok().or_else(|| s.parse().ok())
}

// Invalid URLTest tolerance or compatibility sniffing timeout does not justify
// rejecting the configuration; keep the documented default. Refuse non-finite
// and negative values rather than letting `as u64` saturate to `u64::MAX` or zero.
fn lenient_duration_ms(
    value: &str,
    setting: &str,
    default: u64,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> u64 {
    lenient(
        crate::types::parse_duration_ms(value),
        default,
        diagnostics,
        || ConfigDiagnostic {
            setting: setting.to_string(),
            value: value.to_string(),
            message: format!(
                "duration is not milliseconds, `ms` or `s`; keeping the default ({default}ms)"
            ),
        },
    )
}

fn parse_ip_prefer(s: &str) -> Option<crate::dns::DnsStrategy> {
    use crate::dns::DnsStrategy;
    // dae `ipversion_prefer` is a *preference*, not an only-mode: 4/6 map to
    // the prefer variants (other family still answered when it alone exists),
    // and 0 is dae's "no preference", the same as omitting the setting.
    match s.parse::<i32>() {
        Ok(0) => Some(DnsStrategy::Both),
        Ok(4) => Some(DnsStrategy::PreferIpv4),
        Ok(6) => Some(DnsStrategy::PreferIpv6),
        _ => None,
    }
}
