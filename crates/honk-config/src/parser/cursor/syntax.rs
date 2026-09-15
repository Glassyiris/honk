use super::Root;
use crate::parser::lexer::{QuoteMode, Source, Span, Token, TokenKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scope {
    Root,
    Unknown,
    Include,
    Fields,
    Nodes,
    Subscriptions,
    SubscriptionFields(usize),
    Groups,
    Dns,
    DnsRules,
    Rules,
}

impl Scope {
    pub fn quotes(self) -> QuoteMode {
        match self {
            Self::Include => QuoteMode::IncludePaths,
            Self::Nodes | Self::Subscriptions => QuoteMode::Entries,
            Self::Fields | Self::SubscriptionFields(_) | Self::Dns => QuoteMode::Declarations,
            Self::Root | Self::Unknown | Self::Groups | Self::DnsRules | Self::Rules => {
                QuoteMode::Ordinary
            }
        }
    }

    pub fn child(self, source: &Source<'_>, header: Header) -> Self {
        match self {
            Self::Root => match Root::parse(source.raw(header.span)) {
                Some(Root::Include) => Self::Include,
                Some(Root::Global | Root::Experimental) => Self::Fields,
                Some(Root::Node) => Self::Nodes,
                Some(Root::Subscription) => Self::Subscriptions,
                Some(Root::Group) => Self::Groups,
                Some(Root::Dns) => Self::Dns,
                Some(Root::Routing) => Self::Rules,
                None => Self::Unknown,
            },
            Self::Groups | Self::SubscriptionFields(_) => Self::Fields,
            Self::Subscriptions => header
                .empty_value_colon(source)
                .map_or(Self::Subscriptions, Self::SubscriptionFields),
            Self::Dns => {
                if source.raw(header.span) == "routing" {
                    Self::DnsRules
                } else {
                    Self::Fields
                }
            }
            scope => scope,
        }
    }

    fn entries(self) -> bool {
        matches!(self, Self::Nodes | Self::Subscriptions)
    }

    fn dynamic_headers(self) -> bool {
        self.entries() || self == Self::Groups
    }

    fn ignores_heads(self) -> bool {
        !matches!(
            self,
            Self::Root | Self::Nodes | Self::Subscriptions | Self::Groups
        )
    }

    pub fn continues_expressions(self) -> bool {
        self == Self::Rules
    }
}

#[derive(Clone, Copy)]
pub(super) struct Header {
    pub span: Span,
    colon: Option<usize>,
    quoted_head: Option<usize>,
    arrow: bool,
}

impl Header {
    pub fn ending_at(self, end: usize) -> Self {
        Self {
            span: Span { end, ..self.span },
            ..self
        }
    }

    fn empty_value_colon(self, source: &Source<'_>) -> Option<usize> {
        self.colon
            .filter(|colon| source.text()[colon + 1..self.span.end].trim().is_empty())
    }

    fn entry_has_value(self, source: &Source<'_>) -> bool {
        if let Some(end) = self.quoted_head {
            return source.text()[end..self.span.end]
                .trim()
                .strip_prefix(':')
                .is_none_or(|value| !value.trim().is_empty());
        }
        self.colon
            .is_some_and(|colon| !source.text()[colon + 1..self.span.end].trim().is_empty())
    }
}

#[derive(Clone, Copy)]
pub(super) struct Compact {
    pub token: usize,
    pub declaration_end: bool,
    legacy_end: bool,
}

pub(super) struct Statement {
    pub segment: usize,
    pub start: usize,
    pub end: usize,
    pub header: Header,
    pub ignored: bool,
    pub parentheses: usize,
    pub compact: Option<Compact>,
    declaration: bool,
    scope: Scope,
}

impl Statement {
    pub fn new(
        source: &Source<'_>,
        token: &Token,
        index: usize,
        segment: usize,
        scope: Scope,
        parentheses: usize,
    ) -> Self {
        let ignored = scope.ignores_heads() && source.raw(token.span).starts_with("/*");
        let mut statement = Self {
            segment,
            start: index,
            end: index,
            header: Header {
                span: token.span,
                colon: None,
                quoted_head: token
                    .quoted
                    .first()
                    .filter(|quote| quote.start == token.span.start)
                    .map(|quote| quote.end),
                arrow: false,
            },
            ignored,
            parentheses,
            compact: None,
            declaration: !ignored,
            scope,
        };
        statement.push(source, token, index);
        statement
    }

    pub fn push(&mut self, source: &Source<'_>, token: &Token, index: usize) {
        let tracks_parentheses =
            !self.ignored && !matches!(self.scope, Scope::Root | Scope::Groups);
        self.compact = None;
        if index > self.start
            && !self.ignored
            && token.kind == TokenKind::Word
            && source.raw(token.span) == "{}"
        {
            if self.scope.entries() && self.declaration && self.parentheses == 0 {
                self.declaration = !self.header.entry_has_value(source);
            }
            self.compact = Some(Compact {
                token: index,
                declaration_end: self.declaration && (!tracks_parentheses || self.parentheses == 0),
                legacy_end: self.scope != Scope::Root
                    && (!self.scope.continues_expressions() || self.parentheses == 0),
            });
        }
        self.end = index + 1;
        self.header.span.end = token.span.end;
        for part in token.unquoted_parts() {
            let bytes = source.raw(part).as_bytes();
            for (offset, &byte) in bytes.iter().enumerate() {
                match byte {
                    b':' if self.header.colon.is_none() => {
                        self.header.colon = Some(part.start + offset)
                    }
                    b'-' if bytes.get(offset + 1) == Some(&b'>') => self.header.arrow = true,
                    b'(' if tracks_parentheses => self.parentheses += 1,
                    b')' if tracks_parentheses => {
                        self.parentheses = self.parentheses.saturating_sub(1)
                    }
                    _ => {}
                }
            }
        }
        if self.scope == Scope::Root {
            self.declaration &= self.header.colon.is_none();
        } else if !self.scope.dynamic_headers() {
            self.declaration &= self.header.colon.is_none() && !self.header.arrow;
        }
    }

    pub fn starts_new_head(&self) -> bool {
        self.compact.is_some_and(|compact| compact.declaration_end)
    }

    pub fn split_before(&self, next: TokenKind) -> bool {
        self.starts_new_head() && (self.scope == Scope::Root || next != TokenKind::OpenBrace)
    }

    pub fn ends_compact(&self) -> bool {
        self.compact
            .is_some_and(|compact| compact.declaration_end || compact.legacy_end)
    }

    pub fn split_include(&self, source: &Source<'_>) -> bool {
        self.scope == Scope::Root && source.raw(self.header.span) == "include"
    }
}
