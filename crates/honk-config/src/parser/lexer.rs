// Scaffolding for future parser development.
#![allow(dead_code)]

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    Ident,
    String,
    Number,
    Colon,
    OpenBrace,
    CloseBrace,
    Arrow,
    Comma,
    AndAnd,
    LParen,
    RParen,
    Eof,
}

pub fn tokenize(_input: &str) -> Vec<Token> {
    vec![]
}
