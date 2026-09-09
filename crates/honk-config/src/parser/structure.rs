use std::path::Path;

use crate::{ConfigDiagnostic, ConfigError};

#[derive(Debug, PartialEq, Eq)]
pub struct Block {
    pub name: String,
    pub items: Vec<Item>,
    pub line: usize,
    pub header: String,
    pub closing: String,
    pub include_body: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Item {
    Statement(String, usize),
    Block(Block),
}

impl Block {
    /// Return the ambient lines represented by this block for a consumer that
    /// recognises the named blocks in `recognised`.
    pub fn lines_except<'a>(&'a self, recognised: &[&str]) -> Vec<&'a str> {
        let mut lines = Vec::new();
        self.append_lines(recognised, &mut lines);
        lines
    }

    fn append_lines<'a>(&'a self, recognised: &[&str], lines: &mut Vec<&'a str>) {
        for item in &self.items {
            match item {
                Item::Statement(line, _) => lines.push(line.as_str()),
                Item::Block(block) => {
                    if recognised.contains(&block.name.as_str()) {
                        continue;
                    }
                    lines.push(block.header.as_str());
                    block.append_lines(recognised, lines);
                    lines.push(block.closing.as_str());
                }
            }
        }
    }

    /// Return direct named children in source order.
    pub fn blocks_any(&self) -> impl Iterator<Item = &Block> {
        self.items.iter().filter_map(|item| match item {
            Item::Block(block) => Some(block),
            Item::Statement(_, _) => None,
        })
    }

    pub fn blocks_matching<'a>(&'a self, recognised: &[&str]) -> Vec<&'a Block> {
        let mut blocks = Vec::new();
        self.append_matching(recognised, &mut blocks);
        blocks
    }

    fn append_matching<'a>(&'a self, recognised: &[&str], blocks: &mut Vec<&'a Block>) {
        for block in self.blocks_any() {
            if recognised.contains(&block.name.as_str()) {
                blocks.push(block);
            } else {
                block.append_matching(recognised, blocks);
            }
        }
    }
}

/// Scan dae's brace structure without interpreting settings or expressions.
///
/// `source` is used only for the include-specific error wording.  Includes are
/// bounded and retained as raw blocks, but their path patterns are deliberately
/// left to the include reader in the next parser layer.
/// `saw_include` remains set on errors so file loading preserves include error mapping.
pub fn scan(
    input: &str,
    source: Option<&Path>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
    saw_include: &mut bool,
) -> Result<Vec<Block>, ConfigError> {
    let lines = Line::all(input);
    let mut scanner = Scanner::default();
    let mut position = (0, 0);
    while position.0 < lines.len() {
        let next = scanner.process_line(input, &lines, position, source, diagnostics);
        *saw_include |= scanner.saw_include;
        position = next?;
    }

    if let Some(frame) = scanner.frames.last() {
        return Err(ConfigError::Parse(format!(
            "unclosed block `{}` opened at line {}",
            frame.name, frame.line
        )));
    }
    Ok(scanner.roots)
}

/// Return the byte index immediately after the matching quote.  A backslash
/// skips the next byte, exactly as the old parser helper did.
pub fn quoted_end(bytes: &[u8], start: usize) -> Option<usize> {
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

#[derive(Debug)]
struct Line<'a> {
    text: &'a str,
    start: usize,
    number: usize,
}

impl<'a> Line<'a> {
    fn all(input: &'a str) -> Vec<Self> {
        input
            .lines()
            .enumerate()
            .map(|(index, text)| Self {
                text,
                start: text.as_ptr() as usize - input.as_ptr() as usize,
                number: index + 1,
            })
            .collect()
    }
}

#[derive(Debug, Default)]
struct Scanner {
    roots: Vec<Block>,
    frames: Vec<Block>,
    braces: Vec<Brace>,
    pending_include: Option<usize>,
    saw_include: bool,
}

#[derive(Debug)]
enum Brace {
    Named,
    Anonymous,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum IncludeCandidate {
    Open(usize),
    Pending,
}

impl Scanner {
    fn process_line(
        &mut self,
        input: &str,
        lines: &[Line<'_>],
        (index, cursor): (usize, usize),
        source: Option<&Path>,
        diagnostics: &mut Vec<ConfigDiagnostic>,
    ) -> Result<(usize, usize), ConfigError> {
        let line_text = lines[index].text;
        let line_number = lines[index].number;

        if let Some(pending_line) = self.pending_include {
            let trimmed_start = line_text.len() - line_text.trim_start().len();
            let bytes = line_text.as_bytes();
            if trimmed_start < bytes.len() && bytes[trimmed_start] == b'{' {
                self.pending_include = None;
                return self.process_include(
                    input,
                    lines,
                    index,
                    trimmed_start,
                    pending_line,
                    source,
                );
            }
            if line_text.trim().is_empty() || line_text.trim_start().starts_with('#') {
                return Ok((index + 1, 0));
            }
            self.pending_include = None;
        }

        if self.at_root() {
            match include_candidate(line_text, cursor) {
                Some(IncludeCandidate::Open(brace)) => {
                    return self.process_include(input, lines, index, brace, line_number, source);
                }
                Some(IncludeCandidate::Pending) => {
                    self.pending_include = Some(line_number);
                    return Ok((index + 1, 0));
                }
                None => {}
            }
        }

        Ok(
            match self.process_normal_line(line_text, line_number, cursor, diagnostics)? {
                Some(cursor) => (index, cursor),
                None => (index + 1, 0),
            },
        )
    }

    fn process_include(
        &mut self,
        input: &str,
        lines: &[Line<'_>],
        line_index: usize,
        brace: usize,
        header_line: usize,
        source: Option<&Path>,
    ) -> Result<(usize, usize), ConfigError> {
        self.saw_include = true;
        let open = lines[line_index].start + brace;
        let body_start = open + 1;
        let close = find_include_close(input, body_start);
        let close = match close {
            Some(close) => close,
            None => {
                if let Some(source) = source {
                    return Err(ConfigError::Include(format!(
                        "unclosed include section in '{}'",
                        source.display()
                    )));
                }
                return Err(ConfigError::Parse(format!(
                    "unclosed block `include` opened at line {header_line}"
                )));
            }
        };

        self.roots.push(Block {
            name: "include".to_string(),
            items: Vec::new(),
            line: header_line,
            header: "include {".to_string(),
            closing: "}".to_string(),
            include_body: Some(input[body_start..close].to_string()),
        });

        let close_line = line_for_offset(lines, close);
        Ok((close_line, close - lines[close_line].start + 1))
    }

    fn process_normal_line(
        &mut self,
        text: &str,
        line: usize,
        start: usize,
        diagnostics: &mut Vec<ConfigDiagnostic>,
    ) -> Result<Option<usize>, ConfigError> {
        let remainder = &text[start..];
        let trimmed = remainder.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(None);
        }

        let bytes = text.as_bytes();
        let mut index = start;
        let mut segment_start = start;
        let mut after_boundary = false;

        while index < bytes.len() {
            if after_boundary
                && bytes[index] == b'#'
                && text[segment_start..index].trim().is_empty()
            {
                return Ok(None);
            }
            match bytes[index] {
                b'\'' | b'"' => {
                    if let Some(end) = quoted_end(bytes, index) {
                        index = end;
                    } else {
                        // An unmatched quote is ordinary text.  In
                        // particular, braces after it remain structural.
                        index += 1;
                    }
                    continue;
                }
                b'{' => {
                    let in_subscription =
                        self.frames.iter().any(|block| block.name == "subscription");
                    if let Some(name) = named_opener(text, segment_start, index, in_subscription) {
                        self.frames.push(Block {
                            name: name.to_string(),
                            items: Vec::new(),
                            line,
                            header: text[segment_start..=index].trim().to_string(),
                            closing: String::new(),
                            include_body: None,
                        });
                        self.braces.push(Brace::Named);
                        segment_start = index + 1;
                        after_boundary = true;
                    } else {
                        if self.frames.is_empty() && self.braces.is_empty() {
                            return Err(ConfigError::Parse(format!(
                                "unexpected `{{` at line {line}"
                            )));
                        }
                        self.braces.push(Brace::Anonymous);
                    }
                    index += 1;
                }
                b'}' => {
                    let brace = self.braces.last();
                    match brace {
                        Some(Brace::Anonymous) => {
                            self.braces.pop();
                            index += 1;
                        }
                        Some(Brace::Named) => {
                            self.push_statement(text, segment_start, index, line, after_boundary);
                            self.braces.pop();
                            let mut frame =
                                self.frames.pop().expect("named brace always has a frame");
                            frame.closing = if text[index + 1..].trim_start().starts_with('#') {
                                text[index..].trim().to_string()
                            } else {
                                "}".to_string()
                            };
                            if let Some(parent) = self.frames.last_mut() {
                                parent.items.push(Item::Block(frame));
                            } else {
                                self.roots.push(frame);
                                return Ok(Some(index + 1));
                            }
                            segment_start = index + 1;
                            after_boundary = true;
                            index += 1;
                        }
                        None => {
                            diagnostics.push(ConfigDiagnostic {
                                setting: String::new(),
                                value: line.to_string(),
                                message: "unmatched `}` ignored".to_string(),
                            });
                            return Ok(None);
                        }
                    }
                }
                _ => index += 1,
            }
        }

        self.push_statement(text, segment_start, bytes.len(), line, after_boundary);
        Ok(None)
    }

    fn push_statement(
        &mut self,
        text: &str,
        start: usize,
        end: usize,
        line: usize,
        after_boundary: bool,
    ) {
        let statement = text[start..end].trim();
        if statement.is_empty() || (after_boundary && statement.starts_with('#')) {
            return;
        }
        if let Some(frame) = self.frames.last_mut() {
            frame
                .items
                .push(Item::Statement(statement.to_string(), line));
        }
    }

    fn at_root(&self) -> bool {
        self.frames.is_empty() && self.braces.is_empty()
    }
}

fn named_opener(
    text: &str,
    segment_start: usize,
    brace: usize,
    in_subscription: bool,
) -> Option<&str> {
    let prefix = text[segment_start..brace].trim();
    if prefix.is_empty() {
        return None;
    }
    let rest_is_blank = text[brace + 1..].trim().is_empty();
    if rest_is_blank
        || (in_subscription
            && prefix
                .split_once(':')
                .is_some_and(|(_, value)| value.trim().is_empty()))
    {
        return Some(prefix);
    }

    if !text[..brace]
        .chars()
        .next_back()
        .is_some_and(char::is_whitespace)
    {
        return None;
    }
    if prefix.chars().any(char::is_whitespace) {
        return None;
    }
    if prefix
        .chars()
        .any(|character| matches!(character, '\'' | '"' | '(' | ')' | '{' | '}'))
    {
        return None;
    }
    Some(prefix)
}

fn include_candidate(text: &str, cursor: usize) -> Option<IncludeCandidate> {
    let bytes = text.as_bytes();
    let start = text.len() - text[cursor..].trim_start().len();
    if !text[start..].starts_with("include") {
        return None;
    }
    let mut index = start + "include".len();
    if index < bytes.len()
        && !bytes[index].is_ascii_whitespace()
        && !matches!(bytes[index], b'{' | b'#')
    {
        return None;
    }
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if index == bytes.len() || bytes[index] == b'#' {
        Some(IncludeCandidate::Pending)
    } else if bytes[index] == b'{' {
        Some(IncludeCandidate::Open(index))
    } else {
        None
    }
}

fn find_include_close(input: &str, body_start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut depth = 1usize;
    let mut index = body_start;
    while index < bytes.len() {
        match bytes[index] {
            b'#' => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'\'' | b'"' => {
                index = quoted_end(bytes, index)?;
            }
            b'{' => {
                depth += 1;
                index += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    None
}

fn line_for_offset(lines: &[Line<'_>], offset: usize) -> usize {
    let mut low = 0usize;
    let mut high = lines.len();
    while low + 1 < high {
        let middle = (low + high) / 2;
        if lines[middle].start <= offset {
            low = middle;
        } else {
            high = middle;
        }
    }
    low
}

#[cfg(test)]
mod tests;
