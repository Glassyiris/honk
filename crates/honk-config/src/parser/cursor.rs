//! Structural indexing and bounded traversal over canonical source-backed segments.

use std::ops::Range;

use super::lexer::{Lexer, Source, Span, Token, TokenKind};
use crate::diagnostic::{DetailedDiagnostic, SettingPath, Severity};
use crate::error::{DetailedConfigError, ErrorCategory};

mod syntax;
use syntax::{Scope, Statement};

/// The root sections a document can carry. One list, matched exhaustively by
/// the reader dispatch, so this cannot silently diverge from section admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    Include,
    Global,
    Node,
    Group,
    Subscription,
    Routing,
    Dns,
    Experimental,
}

impl Root {
    pub const ALL: [Root; 8] = [
        Root::Include,
        Root::Global,
        Root::Node,
        Root::Group,
        Root::Subscription,
        Root::Routing,
        Root::Dns,
        Root::Experimental,
    ];

    pub fn parse(name: &str) -> Option<Root> {
        Root::ALL.into_iter().find(|root| root.name() == name)
    }

    /// These readers can omit a malformed quoted contribution when every block closes.
    pub fn recovers_from_quote_errors(self) -> bool {
        matches!(self, Root::Group | Root::Node | Root::Dns)
    }

    pub fn name(self) -> &'static str {
        match self {
            Root::Include => "include",
            Root::Global => "global",
            Root::Node => "node",
            Root::Group => "group",
            Root::Subscription => "subscription",
            Root::Routing => "routing",
            Root::Dns => "dns",
            Root::Experimental => "experimental",
        }
    }
}

/// Related opener coordinates stay local until diagnostics support related spans.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct StructureError {
    pub error: DetailedConfigError,
    pub unclosed: Option<Span>,
    /// Whether a root-level include opener was indexed before failure.
    pub saw_include: bool,
}

#[derive(Debug, Clone, Copy)]
enum SegmentKind {
    Statement,
    Ignored,
    Compact,
    Braced(usize),
}

#[derive(Debug)]
struct IndexedSegment {
    range: Range<usize>,
    kind: SegmentKind,
    next: usize,
    scope: Scope,
}

#[derive(Debug)]
pub struct Document<'a> {
    source: Source<'a>,
    tokens: Vec<Token>,
    comments: Vec<Token>,
    segments: Vec<IndexedSegment>,
    sections: Vec<usize>,
}

struct Frame {
    owner: Option<usize>,
    scope: Scope,
    parentheses: usize,
    quote: Option<usize>,
}

struct Indexer<'a> {
    doc: Document<'a>,
    frames: Vec<Frame>,
    pending: Option<Statement>,
    routing_parentheses: usize,
    comment_braces: Vec<Span>,
    saw_open: bool,
    saw_include: bool,
}

impl<'a> Document<'a> {
    /// Standalone structural attempt, including one terminal diagnostic on failure.
    pub fn parse(
        source: Source<'a>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) -> Result<Self, StructureError> {
        let result = Self::parse_attempt(source, diagnostics, true);
        if let Err(error) = &result {
            diagnostics.push((*error.error.diagnostic).clone());
        }
        result
    }

    pub(super) fn parse_attempt(
        source: Source<'a>,
        diagnostics: &mut Vec<DetailedDiagnostic>,
        require_block: bool,
    ) -> Result<Self, StructureError> {
        Indexer {
            doc: Self {
                source,
                tokens: Vec::new(),
                comments: Vec::new(),
                segments: Vec::new(),
                sections: Vec::new(),
            },
            frames: vec![Frame {
                owner: None,
                scope: Scope::Root,
                parentheses: 0,
                quote: None,
            }],
            pending: None,
            routing_parentheses: 0,
            comment_braces: Vec::new(),
            saw_open: false,
            saw_include: false,
        }
        .parse(diagnostics, require_block)
    }

    pub fn source(&self) -> &Source<'a> {
        &self.source
    }

    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    pub fn sections(&self) -> impl DoubleEndedIterator<Item = Segment<'_, 'a>> {
        self.sections
            .iter()
            .map(|&index| Segment { doc: self, index })
    }

    fn range_span(&self, range: Range<usize>) -> Span {
        self.source.span(
            self.tokens[range.start].span.start,
            self.tokens[range.end - 1].span.end,
        )
    }

    fn header_span(&self, index: usize) -> Span {
        let segment = &self.segments[index];
        let end = match segment.kind {
            SegmentKind::Statement | SegmentKind::Ignored => segment.range.end,
            SegmentKind::Compact => segment.range.end - 1,
            SegmentKind::Braced(open) => open,
        };
        self.range_span(segment.range.start..end)
    }
}

impl<'a> Indexer<'a> {
    fn root(&self) -> Option<Root> {
        let owner = self.frames.get(1)?.owner?;
        Root::parse(self.doc.source.raw(self.doc.header_span(owner)))
    }

    fn push_statement_token(&mut self, index: usize) {
        let frame = self.frames.last().unwrap();
        let token = &self.doc.tokens[index];
        if let Some(statement) = &mut self.pending {
            statement.push(&self.doc.source, token, index);
            self.doc.segments[statement.segment].range.end = index + 1;
        } else {
            let segment = self.doc.segments.len();
            let statement = Statement::new(
                &self.doc.source,
                token,
                index,
                segment,
                frame.scope,
                frame.parentheses,
            );
            self.doc.segments.push(IndexedSegment {
                range: index..index + 1,
                kind: if statement.ignored {
                    SegmentKind::Ignored
                } else {
                    SegmentKind::Statement
                },
                next: segment + 1,
                scope: frame.scope,
            });
            self.pending = Some(statement);
        }
    }

    fn finish_statement(&mut self, diagnostics: &mut Vec<DetailedDiagnostic>) {
        let frame = self.frames.last_mut().unwrap();
        let Some(statement) = self.pending.take() else {
            return;
        };
        let compact = statement.ends_compact();
        let header = if compact {
            let token = statement.compact.unwrap().token;
            statement
                .header
                .ending_at(self.doc.tokens[token - 1].span.end)
        } else {
            statement.header
        };
        let next = self.doc.segments.len();
        let segment = &mut self.doc.segments[statement.segment];
        if compact {
            segment.kind = SegmentKind::Compact;
            segment.scope = frame.scope.child(&self.doc.source, header);
        } else if frame.scope.continues_expressions() && !statement.ignored {
            frame.parentheses = statement.parentheses;
        }
        segment.next = next;
        if frame.scope != Scope::Root {
            return;
        }
        if compact {
            self.saw_open = true;
            let last = &self.doc.tokens[statement.end - 1];
            if last.line != self.doc.tokens[statement.start].line {
                diagnostics.push(self.doc.source.diagnostic(
                    last.span,
                    Severity::Warning,
                    "legacy-include-opener",
                    "put the include opener on its header line",
                ));
            }
            match Root::parse(self.doc.source.raw(header.span)) {
                Some(root) => {
                    self.saw_include |= root == Root::Include;
                    self.doc.sections.push(statement.segment);
                }
                None => diagnostics.push(self.doc.source.diagnostic(
                    last.span,
                    Severity::Warning,
                    "unknown-block",
                    "unknown top-level block ignored",
                )),
            }
        } else {
            let code = if self.doc.source.raw(header.span).starts_with("/*") {
                "unsupported-comment"
            } else {
                "unknown-statement"
            };
            diagnostics.push(self.doc.source.diagnostic(
                header.span,
                Severity::Warning,
                code,
                "unknown top-level statement ignored",
            ));
        }
    }

    fn open_block(
        &mut self,
        statement: Statement,
        index: usize,
        diagnostics: &mut Vec<DetailedDiagnostic>,
    ) {
        let frame = self.frames.last().unwrap();
        let scope = frame.scope.child(&self.doc.source, statement.header);
        let root = frame.scope == Scope::Root;
        let name = self.doc.source.raw(statement.header.span);
        if self.doc.tokens[index].line != self.doc.tokens[statement.start].line {
            diagnostics.push(self.doc.source.diagnostic(
                self.doc.tokens[index].span,
                Severity::Warning,
                "legacy-include-opener",
                "put the include opener on its header line",
            ));
        }
        if root {
            self.saw_include |= name == "include";
            if Root::parse(name).is_none() {
                diagnostics.push(self.doc.source.diagnostic(
                    self.doc.tokens[index].span,
                    Severity::Warning,
                    "unknown-block",
                    "unknown top-level block ignored",
                ));
            }
        }
        let segment = &mut self.doc.segments[statement.segment];
        segment.kind = SegmentKind::Braced(index);
        segment.range.end = index + 1;
        segment.scope = scope;
        self.frames.push(Frame {
            owner: Some(statement.segment),
            scope,
            parentheses: if root && scope.continues_expressions() {
                self.routing_parentheses
            } else {
                0
            },
            quote: None,
        });
        self.saw_open = true;
    }

    fn close_block(&mut self, index: usize, diagnostics: &mut Vec<DetailedDiagnostic>) {
        self.finish_statement(diagnostics);
        if self.frames.len() == 1 {
            diagnostics.push(self.doc.source.diagnostic(
                self.doc.tokens[index].span,
                Severity::Warning,
                "unmatched-close",
                "unmatched closing brace ignored",
            ));
            return;
        }
        let frame = self.frames.pop().unwrap();
        let owner = frame.owner.unwrap();
        let next = self.doc.segments.len();
        let segment = &mut self.doc.segments[owner];
        segment.range.end = index + 1;
        segment.next = next;
        if self.frames.len() == 1 {
            if frame.scope.continues_expressions() {
                self.routing_parentheses = frame.parentheses;
            }
            if Root::parse(self.doc.source.raw(self.doc.header_span(owner))).is_some() {
                self.doc.sections.push(owner);
            }
        }
    }

    fn parse(
        mut self,
        diagnostics: &mut Vec<DetailedDiagnostic>,
        require_block: bool,
    ) -> Result<Document<'a>, StructureError> {
        let attempt_start = diagnostics.len();
        let mut lexer = Lexer::default();
        let mut fatal = None;
        loop {
            let frame = self.frames.last().unwrap();
            if self
                .pending
                .as_ref()
                .is_some_and(Statement::starts_new_head)
            {
                lexer.begin_statement();
            }
            let Some(token) = lexer.next_token(&self.doc.source, frame.scope.quotes()) else {
                break;
            };
            match token.kind {
                TokenKind::Whitespace => continue,
                TokenKind::Newline => {
                    if self.frames.len() != 1 {
                        self.finish_statement(diagnostics);
                    }
                    continue;
                }
                TokenKind::Comment => {
                    let root = self.root();
                    if self.doc.source.raw(token.span).contains(['{', '}'])
                        && self.frames.len() > 1
                        && root != Some(Root::Include)
                        && (root != Some(Root::Dns)
                            || self
                                .doc
                                .tokens
                                .last()
                                .is_some_and(|last| last.line == token.line))
                    {
                        self.comment_braces.push(token.span);
                    }
                    self.doc.comments.push(token);
                    continue;
                }
                _ => {}
            }
            let kind = token.kind;
            let index = self.doc.tokens.len();
            let line = token.line;
            let span = token.span;
            self.doc.tokens.push(token);
            let split = self.pending.as_ref().is_some_and(|statement| {
                statement.split_before(kind)
                    || (self.frames.len() == 1
                        && self.doc.tokens[statement.start].line != line
                        && !(statement.split_include(&self.doc.source)
                            && (kind == TokenKind::OpenBrace || self.doc.source.raw(span) == "{}")))
            });
            if split {
                self.finish_statement(diagnostics);
            }
            match kind {
                TokenKind::OpenBrace => {
                    let Some(statement) = self.pending.take() else {
                        fatal = Some(self.doc.source.diagnostic(
                            span,
                            Severity::Error,
                            "unexpected-open-brace",
                            "block opener requires a header on the same line",
                        ));
                        break;
                    };
                    self.open_block(statement, index, diagnostics);
                    lexer.begin_statement();
                }
                TokenKind::CloseBrace => {
                    self.close_block(index, diagnostics);
                    lexer.begin_statement();
                }
                TokenKind::Error { opener } => {
                    let diagnostic = self.doc.source.quote_error(opener, span.end);
                    if !self.root().is_some_and(Root::recovers_from_quote_errors) {
                        fatal = Some(diagnostic);
                        break;
                    }
                    self.push_statement_token(index);
                    let position = diagnostics.len();
                    diagnostics.push(diagnostic);
                    for frame in self.frames.iter_mut().skip(1).rev() {
                        if frame.quote.is_some() {
                            break;
                        }
                        frame.quote = Some(position);
                    }
                }
                TokenKind::Word => {
                    let raw = self.doc.source.raw(span);
                    let glued_empty_root =
                        self.frames.len() == 1 && raw.len() > 2 && raw.ends_with("{}");
                    if (raw.ends_with('{') || glued_empty_root)
                        && !self.doc.tokens[index]
                            .quoted
                            .iter()
                            .any(|quote| quote.end == span.end)
                    {
                        let start = span.end - if glued_empty_root { 2 } else { 1 };
                        fatal = Some(self.doc.source.diagnostic(
                            self.doc.source.span(start, start + 1),
                            Severity::Error,
                            "block-delimiter-spacing",
                            "separate block braces from the header with whitespace",
                        ));
                        break;
                    }
                    self.push_statement_token(index);
                    if self.frames.len() == 1
                        && self
                            .pending
                            .as_ref()
                            .is_some_and(Statement::starts_new_head)
                    {
                        self.finish_statement(diagnostics);
                    }
                }
                _ => unreachable!("trivia was consumed before indexing"),
            }
        }
        for span in &self.comment_braces {
            diagnostics.push(self.doc.source.diagnostic(
                *span,
                Severity::Warning,
                "legacy-comment-brace",
                "comments do not close blocks; put the closer outside the comment",
            ));
        }
        if let Some(diagnostic) = fatal {
            return Err(reject(
                diagnostic,
                None,
                None,
                self.saw_include,
                diagnostics,
            ));
        }
        if let Some(frame) = self
            .frames
            .iter()
            .skip(1)
            .rev()
            .find(|frame| frame.quote.is_some())
            .or_else(|| self.frames.get(1..).unwrap().last())
        {
            let header = self.doc.header_span(frame.owner.unwrap());
            let (mut diagnostic, existing) = if let Some(position) = frame.quote {
                (diagnostics[position].clone(), Some(position))
            } else {
                (
                    self.doc.source.diagnostic(
                        header,
                        Severity::Error,
                        "unclosed-block",
                        "block has no surviving closing brace",
                    ),
                    None,
                )
            };
            if let Some(root) = self.root() {
                diagnostic.setting = SettingPath::new(root.name());
            }
            return Err(reject(
                diagnostic,
                Some(header),
                existing,
                self.saw_include,
                diagnostics,
            ));
        }
        if require_block && !self.saw_open {
            diagnostics.truncate(attempt_start);
            let end = self.doc.source.text().len();
            return Err(reject(
                self.doc.source.diagnostic(
                    self.doc.source.span(end, end),
                    Severity::Error,
                    "not-dae-config",
                    "document contains no block",
                ),
                None,
                None,
                self.saw_include,
                diagnostics,
            ));
        }
        self.finish_statement(diagnostics);
        Ok(self.doc)
    }
}

fn reject(
    mut diagnostic: DetailedDiagnostic,
    unclosed: Option<Span>,
    existing: Option<usize>,
    saw_include: bool,
    diagnostics: &mut Vec<DetailedDiagnostic>,
) -> StructureError {
    diagnostic.terminal = true;
    if let Some(index) = existing {
        diagnostics.remove(index);
    }
    StructureError {
        error: DetailedConfigError {
            category: ErrorCategory::Parse,
            diagnostic: Box::new(diagnostic),
        },
        unclosed,
        saw_include,
    }
}

#[derive(Debug)]
pub struct Segment<'d, 'a> {
    doc: &'d Document<'a>,
    index: usize,
}

impl<'d, 'a> Segment<'d, 'a> {
    fn indexed(&self) -> &'d IndexedSegment {
        &self.doc.segments[self.index]
    }

    pub fn span(&self) -> Span {
        self.doc.range_span(self.indexed().range.clone())
    }

    pub fn header_span(&self) -> Span {
        self.doc.header_span(self.index)
    }

    pub fn header(&self) -> &'d str {
        self.doc.source.raw(self.header_span())
    }

    pub fn body(&self) -> Option<Dispenser<'d, 'a>> {
        matches!(self.indexed().kind, SegmentKind::Braced(_)).then(|| Dispenser {
            doc: self.doc,
            range: self.index + 1..self.indexed().next,
        })
    }

    pub(super) fn subscription_tag(&self) -> Option<Span> {
        if self.is_block()
            && let Scope::SubscriptionFields(end) = self.indexed().scope
        {
            Some(Span {
                end,
                ..self.header_span()
            })
        } else {
            None
        }
    }

    /// The opening token remains available independently of the header span.
    pub(super) fn opening_span(&self) -> Option<Span> {
        let segment = self.indexed();
        match segment.kind {
            SegmentKind::Statement | SegmentKind::Ignored => None,
            SegmentKind::Compact => Some(self.doc.tokens[segment.range.end - 1].span),
            SegmentKind::Braced(open) => Some(self.doc.tokens[open].span),
        }
    }

    pub(super) fn is_block(&self) -> bool {
        matches!(
            self.indexed().kind,
            SegmentKind::Compact | SegmentKind::Braced(_)
        )
    }

    pub(super) fn is_ignored(&self) -> bool {
        matches!(self.indexed().kind, SegmentKind::Ignored)
    }

    pub(super) fn source(&self) -> &'d Source<'a> {
        &self.doc.source
    }

    pub(super) fn comment(&self) -> Option<&'d Token> {
        let segment = self.indexed();
        let end = match segment.kind {
            SegmentKind::Braced(open) => open,
            _ => segment.range.end - 1,
        };
        let last = self.doc.tokens.get(end)?;
        let position = self
            .doc
            .comments
            .partition_point(|comment| comment.span.start < last.span.end);
        self.doc.comments.get(position).filter(|comment| {
            comment.line == last.line
                && self
                    .doc
                    .tokens
                    .get(end + 1)
                    .is_none_or(|next| next.span.start > comment.span.start)
        })
    }

    pub(super) fn tokens(&self) -> &'d [Token] {
        &self.doc.tokens[self.indexed().range.clone()]
    }
}

#[derive(Debug, Clone)]
pub struct Dispenser<'d, 'a> {
    doc: &'d Document<'a>,
    range: Range<usize>,
}

impl<'d, 'a> Iterator for Dispenser<'d, 'a> {
    type Item = Segment<'d, 'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.is_empty() {
            return None;
        }
        let index = self.range.start;
        self.range.start = self.doc.segments[index].next;
        Some(Segment {
            doc: self.doc,
            index,
        })
    }
}

pub fn same_physical_line(left: &Token, right: &Token) -> bool {
    left.span.source == right.span.source && left.line == right.line
}

pub fn adjacent(left: Span, right: Span) -> bool {
    left.source == right.source && left.end == right.start
}
