mod section_parser;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::Config;
use crate::config::GlobalConfig;
use crate::dns::DnsConfig;
use crate::experimental::ExperimentalConfig;
use crate::group::Group;
use crate::node::Node;
use crate::routing::RoutingConfig;
use crate::subscription::Subscription;
use regex::Regex;
use section_parser::Section;

/// Load a dae configuration file, resolving its top-level `include` blocks.
///
/// Include paths are relative to the entry configuration's directory, even
/// when they occur in a nested included file.  Included files must remain
/// below that directory after symlink resolution.
pub fn parse_dae_config_file(path: impl AsRef<Path>) -> Result<Config, crate::ConfigError> {
    let entry = std::fs::canonicalize(path.as_ref())?;
    let entry_dir = entry.parent().map(Path::to_path_buf).ok_or_else(|| {
        crate::ConfigError::Include(format!(
            "entry configuration '{}' has no parent directory",
            entry.display()
        ))
    })?;
    let mut loader = IncludeLoader {
        entry_dir,
        loaded: HashSet::new(),
        stack: Vec::new(),
        saw_include: false,
    };
    let input = loader.expand_file(&entry)?;

    match parse_dae_config(&input) {
        Ok(config) => Ok(config),
        Err(err) if loader.saw_include => Err(crate::ConfigError::Include(format!(
            "failed to parse configuration after resolving includes: {err}"
        ))),
        Err(err) => Err(err),
    }
}

struct IncludeLoader {
    entry_dir: PathBuf,
    // dae treats a repeated include as a circular include too.  Keep that
    // behavior, but canonical paths also prevent symlink aliases escaping it.
    loaded: HashSet<PathBuf>,
    stack: Vec<PathBuf>,
    saw_include: bool,
}

impl IncludeLoader {
    fn expand_file(&mut self, path: &Path) -> Result<String, crate::ConfigError> {
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

        self.stack.push(path.to_path_buf());
        let result = (|| {
            let input = std::fs::read_to_string(path).map_err(|err| {
                crate::ConfigError::Include(format!(
                    "failed to read configuration '{}': {err}",
                    path.display()
                ))
            })?;
            let (has_include, patterns) = extract_include_patterns(&input, path)?;
            self.saw_include |= has_include;

            // dae merges an entry's own sections before the sections of its
            // included descendants, regardless of where `include` occurs in
            // that entry.  Appending recursively gives that preorder.
            let mut expanded = input;
            for pattern in patterns {
                for child in self.expand_pattern(&pattern, path)? {
                    expanded.push('\n');
                    expanded.push_str(&self.expand_file(&child)?);
                }
            }
            Ok(expanded)
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

/// Extract bare or quoted paths from top-level `include { ... }` blocks.
/// This intentionally has a small lexer of its own so the file loader also
/// accepts dae's inline form: `include { 'path with spaces.dae' other.dae }`.
fn extract_include_patterns(
    input: &str,
    source: &Path,
) -> Result<(bool, Vec<String>), crate::ConfigError> {
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut depth = 0usize;
    let mut found = false;
    let mut patterns = Vec::new();

    while index < bytes.len() {
        match bytes[index] {
            b'#' => skip_line(bytes, &mut index),
            b'\'' | b'"' => {
                if let Some(end) = quoted_end(bytes, index) {
                    index = end;
                } else {
                    break;
                }
            }
            b'{' => {
                depth += 1;
                index += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            byte if depth == 0 && is_ident_start(byte) => {
                let start = index;
                index += 1;
                while index < bytes.len() && is_ident_continue(bytes[index]) {
                    index += 1;
                }
                if &input[start..index] != "include" {
                    continue;
                }

                let mut after_name = index;
                skip_layout(bytes, &mut after_name);
                if after_name >= bytes.len() || bytes[after_name] != b'{' {
                    continue;
                }
                let (body, end) = include_body(input, after_name, source)?;
                found = true;
                patterns.extend(parse_include_body(body, source)?);
                index = end;
            }
            _ => index += 1,
        }
    }

    Ok((found, patterns))
}

fn parse_include_body(body: &str, source: &Path) -> Result<Vec<String>, crate::ConfigError> {
    let bytes = body.as_bytes();
    let mut index = 0;
    let mut patterns = Vec::new();

    while index < bytes.len() {
        skip_layout(bytes, &mut index);
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

fn include_body<'a>(
    input: &'a str,
    open_brace: usize,
    source: &Path,
) -> Result<(&'a str, usize), crate::ConfigError> {
    let bytes = input.as_bytes();
    let mut index = open_brace + 1;
    let body_start = index;
    let mut depth = 1usize;

    while index < bytes.len() {
        match bytes[index] {
            b'#' => skip_line(bytes, &mut index),
            b'\'' | b'"' => {
                if let Some(end) = quoted_end(bytes, index) {
                    index = end;
                } else {
                    break;
                }
            }
            b'{' => {
                depth += 1;
                index += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&input[body_start..index], index + 1));
                }
                index += 1;
            }
            _ => index += 1,
        }
    }

    Err(crate::ConfigError::Include(format!(
        "unclosed include section in '{}'",
        source.display()
    )))
}

fn skip_layout(bytes: &[u8], index: &mut usize) {
    loop {
        while *index < bytes.len() && bytes[*index].is_ascii_whitespace() {
            *index += 1;
        }
        if *index < bytes.len() && bytes[*index] == b'#' {
            skip_line(bytes, index);
        } else {
            break;
        }
    }
}

fn skip_line(bytes: &[u8], index: &mut usize) {
    while *index < bytes.len() && bytes[*index] != b'\n' {
        *index += 1;
    }
}

fn quoted_end(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == quote => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_continue(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit() || byte == b'-'
}

pub fn parse_dae_config(input: &str) -> Result<Config, crate::ConfigError> {
    let input = strip_comments(input);
    if !input.contains('{') || !input.contains('}') {
        return Err(crate::ConfigError::Parse("not a dae config file".into()));
    }

    let sections = merge_top_level_sections(split_sections(&input)?);
    let mut config = Config::default();

    for section in &sections {
        match section.name.as_str() {
            "global" => config.global = parse_global_section(section)?,
            "dns" => config.dns = parse_dns_section(section)?,
            "routing" => config.routing = parse_routing_section(section)?,
            "node" => {
                for node in parse_node_section(section)? {
                    config.nodes.push(node);
                }
            }
            "group" => {
                for group in parse_group_section(section)? {
                    config.groups.push(group);
                }
            }
            "subscription" => {
                for sub in parse_subscription_section(section)? {
                    config.subscriptions.push(sub);
                }
            }
            "experimental" => config.experimental = parse_experimental_section(section)?,
            "include" => {}
            _ => {}
        }
    }

    resolve_group_filters(&mut config.groups, &config.nodes);

    Ok(config)
}

/// Resolve group filters into concrete node UUIDs.
///
/// Supports `name('pattern')` where `pattern` is a regular expression matched
/// against the node name. This lets groups include static nodes as well as
/// nodes added dynamically (for example, from a fetched subscription).
///
/// `group('tag')` entries are not node filters — the dae parser routes them
/// into `Group.groups` (nested sub-groups) at parse time; any that still end
/// up here are ignored by node-filter resolution.
pub fn resolve_group_filters(groups: &mut [Group], nodes: &[Node]) {
    for group in groups {
        let filters: Vec<&str> = group
            .filters
            .iter()
            .map(|f| f.trim())
            .filter(|f| !f.starts_with("group("))
            .collect();

        // A group with no filters and no sub-groups includes all nodes.
        // (A group that only names sub-groups must NOT swallow every node.)
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

        for filter in &filters {
            let re = parse_name_filter(filter);
            let Some(re) = re else { continue };
            for node in nodes {
                if re.is_match(&node.name) && !group.nodes.contains(&node.id) {
                    group.nodes.push(node.id);
                }
            }
        }
    }
}

/// Parse a `name(...)` filter into a regex (Go dae `filter.go` parity).
///
/// Supported patterns:
///   name('a', 'b')          — exact match of any listed name (params OR-ed)
///   name(keyword: 'pat')    — substring match
///   name(regex: '^ju')      — raw regex match
fn parse_name_filter(filter: &str) -> Option<Regex> {
    let body = filter
        .strip_prefix("name(")
        .and_then(|s| s.strip_suffix(")"))?;
    let body = body.trim();

    if let Some(keyword) = body.strip_prefix("keyword:") {
        let kw = keyword.trim().trim_matches(|c: char| c == '\'' || c == '"');
        Regex::new(&regex::escape(kw)).ok()
    } else if let Some(pattern) = body.strip_prefix("regex:") {
        let pat = pattern.trim().trim_matches(|c: char| c == '\'' || c == '"');
        Regex::new(pat).ok()
    } else {
        // Plain params: comma-separated exact names, OR-ed — dae matches a
        // node when ANY param equals its name.
        let pattern = body
            .split(',')
            .map(|p| p.trim().trim_matches(|c: char| c == '\'' || c == '"'))
            .filter(|p| !p.is_empty())
            .map(|n| format!("^{}$", regex::escape(n)))
            .collect::<Vec<_>>()
            .join("|");
        if pattern.is_empty() {
            return None;
        }
        Regex::new(&pattern).ok()
    }
}

fn strip_comments(input: &str) -> String {
    input
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn split_sections(input: &str) -> Result<Vec<Section>, crate::ConfigError> {
    let mut sections = Vec::new();
    let mut depth = 0i32;
    let mut current_name = String::new();
    let mut current_body = String::new();
    let mut in_section = false;

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let open_count = trimmed.matches('{').count() as i32;
        let close_count = trimmed.matches('}').count() as i32;

        if !in_section {
            if let Some(name) = trimmed.strip_suffix('{') {
                current_name = name.trim().to_string();
                in_section = true;
                depth = 1;
                current_body.clear();
                if trimmed.contains('}') {
                    depth = 0;
                    in_section = false;
                    sections.push(Section {
                        name: current_name.clone(),
                        body: current_body.clone(),
                    });
                }
            }
        } else {
            depth += open_count;
            depth -= close_count;
            if depth <= 0 {
                in_section = false;
                let line_content = if close_count > 0 {
                    trimmed.trim_end_matches('}').trim()
                } else {
                    trimmed
                };
                if !line_content.is_empty() {
                    current_body.push_str(line_content);
                    current_body.push('\n');
                }
                sections.push(Section {
                    name: current_name.clone(),
                    body: current_body.clone(),
                });
            } else {
                current_body.push_str(trimmed);
                current_body.push('\n');
                for _ in 0..close_count {
                    current_body.push('}');
                }
                if close_count > 0 {
                    current_body.push('\n');
                }
            }
        }
    }

    Ok(sections)
}

/// dae merges repeated top-level sections by appending their items.  Keeping
/// one body per section lets the existing section parsers retain that order
/// when a configuration is composed from include files.
fn merge_top_level_sections(sections: Vec<Section>) -> Vec<Section> {
    let mut merged = Vec::<Section>::new();
    let mut indices = HashMap::<String, usize>::new();

    for section in sections {
        if let Some(&index) = indices.get(&section.name) {
            let body = &mut merged[index].body;
            if !body.is_empty() && !section.body.is_empty() {
                body.push('\n');
            }
            body.push_str(&section.body);
        } else {
            indices.insert(section.name.clone(), merged.len());
            merged.push(section);
        }
    }

    merged
}

fn parse_kv_pairs(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed
            .split_once('#')
            .map(|(l, _)| l.trim())
            .unwrap_or(trimmed);
        if let Some(pos) = trimmed.find(':') {
            let key = trimmed[..pos].trim().to_string();
            let val = trimmed[pos + 1..]
                .trim()
                .trim_matches('\'')
                .trim_matches('"')
                .to_string();
            map.insert(key, val);
        }
    }
    map
}

fn parse_global_section(section: &Section) -> Result<GlobalConfig, crate::ConfigError> {
    let mut cfg = GlobalConfig::default();
    let kv = parse_kv_pairs(&section.body);

    if let Some(v) = kv.get("tproxy_port") {
        cfg.tproxy_port = v.parse().unwrap_or(12345);
    }
    if let Some(v) = kv.get("tproxy_port_protect") {
        cfg.tproxy_port_protect = parse_bool(v);
    }
    if let Some(v) = kv.get("pprof_port") {
        cfg.pprof_port = v.parse().unwrap_or(0);
    }
    if let Some(v) = kv.get("so_mark_from_dae") {
        cfg.so_mark_from_dae = parse_hex_or_dec(v);
    }
    if let Some(v) = kv.get("log_level") {
        cfg.log_level = v.clone();
    }
    if let Some(v) = kv.get("disable_waiting_network") {
        cfg.disable_waiting_network = parse_bool(v);
    }
    if let Some(v) = kv.get("lan_interface") {
        cfg.lan_interface = v.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(v) = kv.get("wan_interface") {
        cfg.wan_interface = v.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(v) = kv.get("auto_config_kernel_parameter") {
        cfg.auto_config_kernel_parameter = parse_bool(v);
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
        cfg.check_interval_secs = parse_duration_secs(v);
    }
    if let Some(v) = kv.get("check_tolerance") {
        cfg.check_tolerance_ms = parse_duration_ms(v);
    }
    if let Some(v) = kv.get("dial_mode") {
        cfg.dial_mode = v.clone();
    }
    if let Some(v) = kv.get("lan_tcp_mss") {
        cfg.lan_tcp_mss = v.parse().unwrap_or(0);
    }
    if let Some(v) = kv.get("allow_insecure") {
        cfg.allow_insecure = parse_bool(v);
    }
    if let Some(v) = kv.get("sniffing_timeout") {
        cfg.sniffing_timeout_ms = parse_duration_ms(v);
    }
    if let Some(v) = kv.get("tls_implementation") {
        cfg.tls_implementation = v.clone();
    }
    if let Some(v) = kv.get("utls_imitate") {
        cfg.utls_imitate = v.clone();
    }
    if let Some(v) = kv.get("tls_fragment") {
        cfg.tls_fragment = parse_bool(v);
    }
    if let Some(v) = kv.get("tls_fragment_length") {
        cfg.tls_fragment_length = v.clone();
    }
    if let Some(v) = kv.get("tls_fragment_interval") {
        cfg.tls_fragment_interval = v.clone();
    }
    if let Some(v) = kv.get("mptcp") {
        cfg.mptcp = parse_bool(v);
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

    Ok(cfg)
}

fn parse_dns_section(section: &Section) -> Result<DnsConfig, crate::ConfigError> {
    let dns_subs =
        split_nested_sections(&section.body, &["upstream", "routing", "fixed_domain_ttl"])?;
    let mut cfg = DnsConfig::default();
    let mut saw_upstream = false;
    let kv = parse_kv_pairs(dns_subs.first().map(|s| s.body.as_str()).unwrap_or(""));

    if let Some(v) = kv.get("ipversion_prefer") {
        cfg.strategy = parse_ip_prefer(v);
    }
    if let Some(v) = kv.get("optimistic_cache") {
        cfg.cache.enabled = parse_bool(v);
    }
    if let Some(v) = kv.get("optimistic_cache_ttl") {
        cfg.cache.ttl = v.parse().unwrap_or(60);
    }
    if let Some(v) = kv.get("max_cache_size") {
        cfg.cache.max_size = v.parse().unwrap_or(10000);
    }

    for sub in dns_subs.iter().skip(1) {
        match sub.name.as_str() {
            "upstream" => {
                if !saw_upstream {
                    cfg.upstream.clear();
                    saw_upstream = true;
                }
                cfg.upstream.extend(parse_dns_upstreams(&sub.body));
            }
            "routing" => {
                for req_body in extract_nested_all(&sub.body, "request") {
                    let has_fallback = has_routing_fallback(&req_body);
                    let request = parse_dns_request_routing(&req_body);
                    cfg.routing.request.rules.extend(request.rules);
                    if !has_fallback {
                        continue;
                    }
                    cfg.routing.request.fallback = request.fallback;
                    // Sync legacy fallback for callers that only look there.
                    if let crate::dns::DnsRequestAction::Upstream(ref name) =
                        cfg.routing.request.fallback
                    {
                        cfg.routing.fallback = name.clone();
                    }
                }
                for resp_body in extract_nested_all(&sub.body, "response") {
                    let has_fallback = has_routing_fallback(&resp_body);
                    let response = parse_dns_response_routing(&resp_body);
                    cfg.routing.response.rules.extend(response.rules);
                    if has_fallback {
                        cfg.routing.response.fallback = response.fallback;
                    }
                }
            }
            "fixed_domain_ttl" => {
                cfg.fixed_domain_ttl
                    .extend(parse_fixed_domain_ttl(&sub.body));
            }
            _ => {}
        }
    }

    Ok(cfg)
}

fn parse_dns_upstreams(body: &str) -> Vec<crate::dns::DnsUpstream> {
    let mut upstreams = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(pos) = trimmed.find(':') {
            let name = trimmed[..pos].trim().to_string();
            let rest = trimmed[pos + 1..].trim();
            // Optional via-proxy suffix (same line):
            //   preferred:  name: 'uri' -> proxy
            //   legacy:     name: 'uri' outbound: proxy
            let (uri, outbound) = if let Some((left, right)) = rest.split_once("->") {
                let uri_part = left.trim().trim_matches('\'').trim_matches('"');
                let outbound_part = right.trim().trim_matches('\'').trim_matches('"');
                let outbound = if outbound_part.is_empty() {
                    None
                } else {
                    Some(outbound_part.to_string())
                };
                (uri_part, outbound)
            } else if let Some(opos) = rest.find("outbound:") {
                let uri_part = rest[..opos].trim().trim_matches('\'').trim_matches('"');
                let outbound_part = rest[opos + 9..].trim().trim_matches('\'').trim_matches('"');
                (uri_part, Some(outbound_part.to_string()))
            } else {
                (rest.trim_matches('\'').trim_matches('"'), None)
            };
            let (protocol, address) = parse_upstream_uri(uri);
            let (address, explicit_sni) = extract_tls_server_name(address);
            let tls_server_name = explicit_sni.or_else(|| sni_from_upstream_address(&address));
            upstreams.push(crate::dns::DnsUpstream {
                name,
                address,
                protocol,
                tls_server_name,
                outbound,
            });
        }
    }
    upstreams
}

fn parse_upstream_uri(uri: &str) -> (crate::types::DnsProtocol, String) {
    let uri = uri.trim();
    if let Some(rest) = uri.strip_prefix("tcp+udp://") {
        (crate::types::DnsProtocol::Udp, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("udp+tcp://") {
        (crate::types::DnsProtocol::Udp, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("h3://") {
        (crate::types::DnsProtocol::H3, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("http3://") {
        (crate::types::DnsProtocol::H3, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("quic://") {
        (crate::types::DnsProtocol::Quic, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("https://") {
        (crate::types::DnsProtocol::Https, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("tls://") {
        (crate::types::DnsProtocol::Tls, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("tcp://") {
        (crate::types::DnsProtocol::Tcp, rest.to_string())
    } else if let Some(rest) = uri.strip_prefix("udp://") {
        (crate::types::DnsProtocol::Udp, rest.to_string())
    } else {
        (crate::types::DnsProtocol::Udp, uri.to_string())
    }
}

/// Derive a TLS SNI hostname from a stripped upstream address.
///
/// Returns `None` when the host is a bare IP (no SNI needed / not useful).
fn sni_from_upstream_address(address: &str) -> Option<String> {
    let hostport = address.split('/').next().unwrap_or(address);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        hostport
            .rsplit_once(':')
            .map(|(h, p)| {
                // Only treat as host:port when the suffix is numeric.
                if p.chars().all(|c| c.is_ascii_digit()) {
                    h
                } else {
                    hostport
                }
            })
            .unwrap_or(hostport)
    };
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    // Bare IPs do not need (and often cannot use) SNI.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(host.to_string())
}

/// Strip an explicit `tls_server_name=` query parameter from an upstream
/// address, e.g. `tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com`.
/// Needed for IP-literal TLS upstreams whose certificate hostname differs
/// from the dial address. Other query pairs are preserved.
fn extract_tls_server_name(address: String) -> (String, Option<String>) {
    let Some(qpos) = address.find('?') else {
        return (address, None);
    };
    let (base, query) = address.split_at(qpos);
    let mut sni = None;
    let mut kept = Vec::new();
    for pair in query[1..].split('&') {
        if let Some(v) = pair.strip_prefix("tls_server_name=") {
            let v = v.trim();
            if !v.is_empty() {
                sni = Some(v.to_string());
            }
        } else if !pair.is_empty() {
            kept.push(pair);
        }
    }
    let address = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    (address, sni)
}

/// Parse `fixed_domain_ttl { domain: N ... }` into a HashMap.
fn parse_fixed_domain_ttl(body: &str) -> std::collections::HashMap<String, u32> {
    let mut map = std::collections::HashMap::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(pos) = trimmed.find(':') {
            let key = trimmed[..pos].trim().trim_matches('"').trim_matches('\'');
            let val = trimmed[pos + 1..].split_whitespace().next().unwrap_or("");
            if let Ok(n) = val.parse::<u32>() {
                map.insert(key.to_string(), n);
            }
        }
    }
    map
}

/// Parse `routing.request { ... }` block.
fn parse_dns_request_routing(body: &str) -> crate::dns::DnsRequestRouting {
    let mut routing = crate::dns::DnsRequestRouting::default();

    for line in body.lines() {
        let mut trimmed = line.trim();
        // Strip trailing inline comment
        if let Some(pos) = trimmed.find("//") {
            trimmed = trimmed[..pos].trim();
        } else if let Some(pos) = trimmed.find('#') {
            // Only strip # if preceded by space (to avoid stripping domain # itself)
            if pos > 0 && trimmed.as_bytes()[pos - 1] == b' ' {
                trimmed = trimmed[..pos].trim();
            }
        }
        if trimmed.is_empty() {
            continue;
        }

        // fallback/default
        if trimmed.starts_with("fallback:") || trimmed.starts_with("default:") {
            let fb = trimmed.split_once(':').unwrap().1.trim();
            routing.fallback = crate::dns::DnsRequestAction::parse(fb);
            continue;
        }

        // Rule: COND -> action
        if let Some(arrow_pos) = trimmed.find("->") {
            let left = trimmed[..arrow_pos].trim();
            let right = trimmed[arrow_pos + 2..].trim();
            let action = crate::dns::DnsRequestAction::parse(right);
            let conditions = parse_dns_conditions(left, false);
            // Skip rules whose conditions were all ignored (e.g. sub()/node()).
            if !conditions.is_empty() {
                routing
                    .rules
                    .push(crate::dns::DnsRequestRule { conditions, action });
            }
        }
    }

    routing
}

/// Parse `routing.response { ... }` block.
fn parse_dns_response_routing(body: &str) -> crate::dns::DnsResponseRouting {
    let mut routing = crate::dns::DnsResponseRouting::default();

    for line in body.lines() {
        let mut trimmed = line.trim();
        // Strip trailing inline comment
        if let Some(pos) = trimmed.find("//") {
            trimmed = trimmed[..pos].trim();
        } else if let Some(pos) = trimmed.find('#')
            && pos > 0
            && trimmed.as_bytes()[pos - 1] == b' '
        {
            trimmed = trimmed[..pos].trim();
        }
        if trimmed.is_empty() {
            continue;
        }

        // fallback/default
        if trimmed.starts_with("fallback:") || trimmed.starts_with("default:") {
            let fb = trimmed.split_once(':').unwrap().1.trim();
            routing.fallback = crate::dns::DnsResponseAction::parse(fb);
            continue;
        }

        // Rule: COND -> action
        if let Some(arrow_pos) = trimmed.find("->") {
            let left = trimmed[..arrow_pos].trim();
            let right = trimmed[arrow_pos + 2..].trim();
            let action = crate::dns::DnsResponseAction::parse(right);
            let conditions = parse_dns_conditions(left, true);
            // Skip rules whose conditions were all ignored (e.g. sub()/node()).
            if !conditions.is_empty() {
                routing
                    .rules
                    .push(crate::dns::DnsResponseRule { conditions, action });
            }
        }
    }

    routing
}

/// Parse a chain of `&&`-separated conditions.
fn parse_dns_conditions(expr: &str, is_response: bool) -> Vec<crate::dns::DnsCond> {
    let mut conds = Vec::new();
    let parts: Vec<&str> = expr.split("&&").map(|s| s.trim()).collect();

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Negation
        let (not, inner) = if let Some(rest) = part.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, part)
        };

        // qname(...)
        if let Some(args) = extract_fn_args(inner, "qname") {
            let matchers = parse_dns_qname_args(&args);
            conds.push(crate::dns::DnsCond::Qname { not, matchers });
            continue;
        }

        // qtype(...)
        if let Some(args) = extract_fn_args(inner, "qtype") {
            let types: Vec<u16> = args
                .iter()
                .filter_map(|a| crate::dns::parse_qtype_token(a))
                .collect();
            conds.push(crate::dns::DnsCond::Qtype { not, types });
            continue;
        }

        // Response-only functions
        if is_response {
            if let Some(args) = extract_fn_args(inner, "upstream") {
                conds.push(crate::dns::DnsCond::Upstream { not, names: args });
                continue;
            }
            if let Some(args) = extract_fn_args(inner, "ip") {
                let (cidrs, geoip) = parse_dns_ip_args(&args);
                conds.push(crate::dns::DnsCond::Ip { not, cidrs, geoip });
                continue;
            }
        }

        // sub() / node() / subnode() — not supported for client DNS, warn
        if inner.starts_with("sub(") || inner.starts_with("node(") || inner.starts_with("subnode(")
        {
            eprintln!(
                "dns routing: ignoring unsupported function {} (out of scope for client DNS)",
                inner
            );
            continue;
        }

        // unknown condition function — silently ignored
    }

    conds
}

/// Parse qname(args) into a list of domain matchers.
fn parse_dns_qname_args(args: &[String]) -> Vec<crate::dns::DnsDomainMatcher> {
    let mut matchers = Vec::new();
    for a in args {
        let a = a.trim();
        if a.is_empty() {
            continue;
        }
        if let Some(v) = strip_tag_arg(a, "geosite:") {
            matchers.push(crate::dns::DnsDomainMatcher::Geosite(
                normalize_geosite_code(&v),
            ));
        } else if let Some(v) = strip_tag_arg(a, "keyword:") {
            matchers.push(crate::dns::DnsDomainMatcher::Keyword(v));
        } else if let Some(v) = strip_tag_arg(a, "full:") {
            matchers.push(crate::dns::DnsDomainMatcher::Full(v));
        } else if let Some(v) = strip_tag_arg(a, "regex:") {
            matchers.push(crate::dns::DnsDomainMatcher::Regex(v));
        } else if let Some(v) = strip_tag_arg(a, "suffix:") {
            matchers.push(crate::dns::DnsDomainMatcher::Suffix(v));
        } else {
            // Bare argument → suffix (dae compatible)
            matchers.push(crate::dns::DnsDomainMatcher::Suffix(a.to_string()));
        }
    }
    matchers
}

/// Parse ip(...) args into (cidrs, geoip_codes).
fn parse_dns_ip_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut cidrs = Vec::new();
    let mut geoip = Vec::new();
    for a in args {
        let a = a.trim();
        if let Some(v) = strip_tag_arg(a, "geoip:") {
            geoip.push(v.to_lowercase());
        } else {
            cidrs.push(a.to_string());
        }
    }
    (cidrs, geoip)
}

fn parse_routing_section(section: &Section) -> Result<RoutingConfig, crate::ConfigError> {
    let mut cfg = RoutingConfig::default();
    let body = section.body.clone();

    for line in body.lines() {
        let trimmed = line.trim();
        let trimmed = trimmed
            .split_once('#')
            .map(|(l, _)| l.trim())
            .unwrap_or(trimmed);
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("fallback:") || trimmed.starts_with("default:") {
            cfg.default_outbound = trimmed.split_once(':').unwrap().1.trim().to_string();
            continue;
        }
        if let Some(arrow_pos) = trimmed.find("->") {
            let left = trimmed[..arrow_pos].trim();
            let right = trimmed[arrow_pos + 2..].trim();
            let (outbound, must) = if let Some(name) = right.strip_suffix("(must)") {
                (name.trim().to_string(), true)
            } else {
                (right.to_string(), false)
            };
            let rule = crate::routing::RoutingRule {
                name: format!("rule-{}", cfg.rules.len()),
                condition: parse_route_condition(left),
                outbound: crate::routing::RoutingOutbound::Simple(outbound),
                priority: cfg.rules.len() as u32,
                must,
                mark: 0,
            };
            cfg.rules.push(rule);
        }
    }

    Ok(cfg)
}

fn parse_route_condition(expr: &str) -> crate::routing::RoutingCondition {
    let mut cond = crate::routing::RoutingCondition::default();
    let parts: Vec<&str> = expr.split("&&").map(|s| s.trim()).collect();

    for part in parts {
        // dae negation: `!` binds to the single matcher that follows it.
        let (not, part) = match part.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, part),
        };
        if part.is_empty() {
            continue;
        }
        let mut target = if not {
            cond.not.fields_mut()
        } else {
            cond.fields_mut()
        };
        if let Some(args) = extract_fn_args(part, "pname") {
            target.process_name.extend(args);
        } else if let Some(args) = extract_fn_args(part, "dip") {
            parse_ip_args(&args, &mut target);
        } else if let Some(args) = extract_fn_args(part, "sip") {
            target.source_ip.extend(args);
        } else if let Some(args) = extract_fn_args(part, "domain") {
            parse_domain_args(&args, &mut target);
        } else if let Some(args) = extract_fn_args(part, "dport") {
            target.port.extend(args);
        } else if let Some(args) = extract_fn_args(part, "sport") {
            target.source_port.extend(args);
        } else if let Some(args) = extract_fn_args(part, "l4proto") {
            target.protocol.extend(args);
        } else if let Some(args) = extract_fn_args(part, "ipversion") {
            target.ip_version.extend(args);
        } else if let Some(args) = extract_fn_args(part, "mac") {
            target.mac.extend(args);
        } else if let Some(args) = extract_fn_args(part, "dscp") {
            target.dscp.extend(args);
        } else {
            // Bare prefix-style conditions used outside function wrappers:
            // geosite:cn, geoip:cn, domain:example.com, suffix:example.com, etc.
            if let Some(v) = strip_tag_arg(part, "geosite:") {
                target.geosite.push(normalize_geosite_code(&v));
            } else if let Some(v) = strip_tag_arg(part, "geoip:") {
                target.geo_ip.push(normalize_geosite_code(&v));
            } else if let Some(v) = strip_tag_arg(part, "domain:") {
                target.domain_suffix.push(v);
            } else if let Some(v) = strip_tag_arg(part, "suffix:") {
                target.domain_suffix.push(v);
            } else if let Some(v) = strip_tag_arg(part, "keyword:") {
                target.domain_keyword.push(v);
            } else if let Some(v) = strip_tag_arg(part, "full:") {
                target.domain.push(v);
            } else if let Some(v) = strip_tag_arg(part, "regex:") {
                target.domain_regex.push(v);
            }
        }
    }

    cond
}

fn extract_fn_args(expr: &str, fn_name: &str) -> Option<Vec<String>> {
    let prefix = format!("{}(", fn_name);
    if let Some(rest) = expr.strip_prefix(&prefix)
        && let Some(end) = rest.find(')')
    {
        let args_str = &rest[..end];
        let args: Vec<String> = args_str
            .split(',')
            .map(|s| s.trim().trim_matches(|c| c == '\'' || c == '"').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        return Some(args);
    }
    None
}

/// Strip a `prefix:` marker from a route argument and trim surrounding
/// whitespace.  Dae syntax allows spaces after the colon (`geosite: cn`).
fn strip_tag_arg(arg: &str, prefix: &str) -> Option<String> {
    arg.strip_prefix(prefix).map(|s| s.trim().to_string())
}

/// Normalize a geosite list name.  Dae uses `list@cn` to request the
/// China-specific variant; the dat files flatten those as `list-cn`.
fn normalize_geosite_code(code: &str) -> String {
    let code = code.trim();
    if code.contains('@') {
        code.replace('@', "-")
    } else {
        code.to_string()
    }
}

/// Dispatch `domain(...)` arguments to the correct condition fields.
/// Supports `suffix:`, `keyword:`, `full:`, `regex:`, and `geosite:`.
fn parse_domain_args(args: &[String], cond: &mut crate::routing::ConditionFields<'_>) {
    for a in args {
        if let Some(v) = strip_tag_arg(a, "geosite:") {
            cond.geosite.push(normalize_geosite_code(&v));
        } else if let Some(v) = strip_tag_arg(a, "keyword:") {
            cond.domain_keyword.push(v);
        } else if let Some(v) = strip_tag_arg(a, "full:") {
            cond.domain.push(v);
        } else if let Some(v) = strip_tag_arg(a, "regex:") {
            cond.domain_regex.push(v);
        } else if let Some(v) = strip_tag_arg(a, "suffix:") {
            cond.domain_suffix.push(v);
        } else {
            // Bare domain argument defaults to suffix matching, mirroring dae.
            cond.domain_suffix.push(a.trim().to_string());
        }
    }
}

/// Dispatch `dip(...)` arguments to the correct condition fields.
/// Supports `geoip:` and plain CIDRs.
fn parse_ip_args(args: &[String], cond: &mut crate::routing::ConditionFields<'_>) {
    for a in args {
        if let Some(v) = strip_tag_arg(a, "geoip:") {
            cond.geo_ip.push(normalize_geosite_code(&v));
        } else {
            cond.ip.push(a.trim().to_string());
        }
    }
}

fn parse_node_section(section: &Section) -> Result<Vec<Node>, crate::ConfigError> {
    let mut nodes = Vec::new();
    for line in section.body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let unquote = |s: &str| s.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
        // Shapes: `tag: 'uri'` | `'tag': 'uri'` | `'uri'` | bare `scheme://uri`.
        // The first colon only splits tag/uri when it sits outside any quotes
        // and is not the URI scheme separator (`://`).
        let (tag, uri) = if trimmed.starts_with(['\'', '"']) {
            let q = trimmed.as_bytes()[0] as char;
            match trimmed[1..].find(q) {
                Some(rel) => {
                    let close = 1 + rel;
                    let after = trimmed[close + 1..].trim_start();
                    if let Some(rest) = after.strip_prefix(':') {
                        (trimmed[1..close].to_string(), unquote(rest))
                    } else {
                        (String::new(), trimmed[1..close].to_string())
                    }
                }
                None => (String::new(), unquote(trimmed)),
            }
        } else if let Some(pos) = trimmed.find(':') {
            if trimmed[pos..].starts_with("://") || trimmed[..pos].contains(char::is_whitespace) {
                (String::new(), trimmed.to_string())
            } else {
                (unquote(&trimmed[..pos]), unquote(&trimmed[pos + 1..]))
            }
        } else {
            (String::new(), unquote(trimmed))
        };
        match Node::from_share_link(&uri) {
            Ok(mut node) => {
                if !tag.is_empty() {
                    node.name = tag;
                }
                nodes.push(node);
            }
            Err(e) => {
                eprintln!("node section: skipping unparseable entry '{trimmed}': {e}");
            }
        }
    }
    Ok(nodes)
}

fn parse_group_section(section: &Section) -> Result<Vec<Group>, crate::ConfigError> {
    let groups_raw = split_nested_sections_named(&section.body)?;
    let mut groups = Vec::new();

    for grp in &groups_raw {
        if grp.name.is_empty() {
            continue; // skip pre-ambient section
        }
        let mut group = Group {
            name: grp.name.clone(),
            ..Default::default()
        };
        let kv = parse_kv_pairs(&grp.body);
        if let Some(policy) = kv.get("policy") {
            group.policy = parse_group_policy(policy);
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

        let filter_lines: Vec<&str> = grp
            .body
            .lines()
            .filter(|l| l.trim().starts_with("filter:"))
            .collect();
        for line in filter_lines {
            let val = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
            // `filter: group('tag', ...)` names nested sub-groups (sing-box
            // style): their tags go to `Group.groups`, everything else stays
            // a node filter resolved by `resolve_group_filters`. Tags may be
            // separated by commas or pipes: `group('hk', 'jp')`, `group('hk|jp')`.
            if let Some(tags) = extract_fn_args(val, "group") {
                for tag in tags
                    .iter()
                    .flat_map(|t| t.split('|').map(str::trim))
                    .map(str::to_string)
                {
                    if !tag.is_empty() && !group.groups.contains(&tag) {
                        group.groups.push(tag);
                    }
                }
            } else {
                group.filters.push(val.to_string());
            }
        }

        groups.push(group);
    }

    Ok(groups)
}

fn parse_group_policy(policy: &str) -> crate::group::GroupPolicy {
    // dae accepts parameterized policies like `fixed(0)` / `min_moving_avg`.
    // Strip the optional `(...)` argument before matching the base name so
    // `policy: fixed(0)` is recognized as Selector (not the default fallthrough).
    let base = policy
        .trim()
        .split_once('(')
        .map(|(name, _)| name.trim())
        .unwrap_or_else(|| policy.trim())
        .to_ascii_lowercase();
    match base.as_str() {
        "select" | "selector" | "fixed" => crate::group::GroupPolicy::Selector,
        "urltest" | "min_moving_avg" | "min_avg10" | "min_last_delay" => {
            crate::group::GroupPolicy::URLTest
        }
        "roundrobin" | "round_robin" | "loadbalance" | "balance" => {
            crate::group::GroupPolicy::LoadBalance
        }
        "fallback" => crate::group::GroupPolicy::Fallback,
        _ => crate::group::GroupPolicy::Selector,
    }
}

fn parse_subscription_section(section: &Section) -> Result<Vec<Subscription>, crate::ConfigError> {
    let mut subs = Vec::new();
    for line in section.body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(pos) = trimmed.find(':') {
            let tag = trimmed[..pos].trim().trim_matches('\'').to_string();
            let url = trimmed[pos + 1..].trim().trim_matches('\'').to_string();
            subs.push(Subscription {
                name: tag,
                url,
                ..Default::default()
            });
        } else if trimmed.starts_with('\'') && trimmed.ends_with('\'') {
            let url = trimmed[1..trimmed.len() - 1].to_string();
            subs.push(Subscription {
                name: url.clone(),
                url,
                ..Default::default()
            });
        }
    }
    Ok(subs)
}

fn parse_experimental_section(section: &Section) -> Result<ExperimentalConfig, crate::ConfigError> {
    let mut cfg = ExperimentalConfig::default();
    let subs = split_nested_sections(&section.body, &["clash_api", "cache_file"])?;

    for sub in &subs {
        let kv = parse_kv_pairs(&sub.body);
        match sub.name.as_str() {
            "clash_api" => {
                if let Some(v) = kv.get("external_controller") {
                    cfg.clash_api.external_controller = v.clone();
                }
                if let Some(v) = kv.get("external_ui") {
                    cfg.clash_api.external_ui = v.clone();
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
                    cfg.cache_file.enabled = parse_bool(v);
                }
                if let Some(v) = kv.get("path") {
                    cfg.cache_file.path = v.clone();
                }
                if let Some(v) = kv.get("cache_id") {
                    cfg.cache_file.cache_id = v.clone();
                }
                if let Some(v) = kv.get("store_fakeip") {
                    cfg.cache_file.store_fakeip = parse_bool(v);
                }
                if let Some(v) = kv.get("store_dns") {
                    cfg.cache_file.store_dns = parse_bool(v);
                }
            }
            _ => {}
        }
    }

    Ok(cfg)
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "true" | "yes" | "1" | "on")
}

fn parse_hex_or_dec(s: &str) -> u32 {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).unwrap_or_else(|_| s.parse().unwrap_or(0))
}

fn parse_duration_secs(s: &str) -> u64 {
    crate::types::parse_duration_secs(s).unwrap_or(0)
}

fn parse_duration_ms(s: &str) -> u64 {
    let s = s.trim();
    if s.ends_with("ms") {
        return s.trim_end_matches("ms").parse().unwrap_or(0);
    }
    if s.ends_with('s') {
        return s
            .trim_end_matches('s')
            .parse::<f64>()
            .map(|v| (v * 1000.0) as u64)
            .unwrap_or(0);
    }
    s.parse::<f64>().map(|v| v as u64).unwrap_or(0)
}

fn parse_ip_prefer(s: &str) -> crate::dns::DnsStrategy {
    use crate::dns::DnsStrategy;
    // dae `ipversion_prefer` is a *preference*, not an only-mode: 4/6 map to
    // the prefer variants (other family still answered when it alone exists).
    match s.parse::<i32>() {
        Ok(4) => DnsStrategy::PreferIpv4,
        Ok(6) => DnsStrategy::PreferIpv6,
        _ => DnsStrategy::PreferIpv4,
    }
}

fn split_nested_sections(body: &str, names: &[&str]) -> Result<Vec<Section>, crate::ConfigError> {
    split_nested_sections_generic(body, names, false)
}

fn split_nested_sections_named(body: &str) -> Result<Vec<Section>, crate::ConfigError> {
    split_nested_sections_generic(body, &[], true)
}

fn split_nested_sections_generic(
    body: &str,
    names: &[&str],
    any_name: bool,
) -> Result<Vec<Section>, crate::ConfigError> {
    let mut sections = vec![Section {
        name: String::new(),
        body: String::new(),
    }];
    let mut depth = 0i32;
    let mut current_name = String::new();
    let mut current_body = String::new();
    let mut in_sub = false;

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let open = trimmed.matches('{').count() as i32;
        let close = trimmed.matches('}').count() as i32;

        if !in_sub {
            if open > 0 && close == 0 {
                if let Some(name) = trimmed.strip_suffix('{') {
                    let name = name.trim().to_string();
                    let matched = any_name || names.contains(&name.as_str());
                    if matched {
                        if !current_body.is_empty() {
                            sections.push(Section {
                                name: current_name.clone(),
                                body: std::mem::take(&mut current_body),
                            });
                        }
                        current_name = name;
                        current_body.clear();
                        in_sub = true;
                        depth = 1;
                    } else {
                        sections.first_mut().unwrap().body.push_str(trimmed);
                        sections.first_mut().unwrap().body.push('\n');
                    }
                } else {
                    sections.first_mut().unwrap().body.push_str(trimmed);
                    sections.first_mut().unwrap().body.push('\n');
                }
            } else {
                sections.first_mut().unwrap().body.push_str(trimmed);
                sections.first_mut().unwrap().body.push('\n');
            }
        } else {
            depth += open;
            depth -= close;
            if depth <= 0 {
                in_sub = false;
                // Take (not clone) the accumulated name/body: leaving them in
                // place would push the same section a second time when the
                // next section opens or at end-of-input.
                sections.push(Section {
                    name: std::mem::take(&mut current_name),
                    body: std::mem::take(&mut current_body),
                });
            } else {
                current_body.push_str(trimmed);
                current_body.push('\n');
            }
        }
    }

    if !current_body.is_empty() && !current_name.is_empty() {
        sections.push(Section {
            name: current_name,
            body: current_body,
        });
    }

    Ok(sections)
}

fn extract_nested_all(body: &str, name: &str) -> Vec<String> {
    split_nested_sections(body, &[name])
        .unwrap_or_default()
        .into_iter()
        .filter(|section| section.name == name)
        .map(|section| section.body)
        .collect()
}

fn has_routing_fallback(body: &str) -> bool {
    body.lines().any(|line| {
        let line = line.trim();
        line.starts_with("fallback:") || line.starts_with("default:")
    })
}
