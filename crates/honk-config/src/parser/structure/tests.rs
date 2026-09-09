use std::path::Path;

use super::{Block, Item, quoted_end, scan};
use crate::{ConfigDiagnostic, ConfigError};

fn scanned(input: &str) -> Vec<Block> {
    let mut diagnostics = Vec::new();
    let blocks =
        scan(input, None, &mut diagnostics, &mut false).expect("scanner input should be valid");
    assert!(
        diagnostics.is_empty(),
        "valid scanner input emitted diagnostics: {diagnostics:?}"
    );
    blocks
}

fn scanned_with_diagnostics(input: &str) -> (Vec<Block>, Vec<ConfigDiagnostic>) {
    let mut diagnostics = Vec::new();
    let blocks =
        scan(input, None, &mut diagnostics, &mut false).expect("scanner input should be valid");
    (blocks, diagnostics)
}

fn parse_error(input: &str, source: Option<&Path>) -> String {
    let mut diagnostics = Vec::new();
    let error =
        scan(input, source, &mut diagnostics, &mut false).expect_err("scanner input should fail");
    match error {
        ConfigError::Parse(message) => message,
        other => panic!("unexpected scanner error: {other:?}"),
    }
}

fn statement(text: &str, line: usize) -> Item {
    Item::Statement(text.to_owned(), line)
}

fn child_names(block: &Block) -> Vec<&str> {
    block
        .blocks_any()
        .map(|child| child.name.as_str())
        .collect()
}

fn projected(block: &Block, recognised: &[&str]) -> Vec<String> {
    block
        .lines_except(recognised)
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[test]
fn lines_comments_and_crlf_preserve_source_line_numbers() {
    let lf = "\n# full comment\n   # indented full comment\n\nglobal {\n  log_level: debug\n}\n";
    let crlf = lf.replace('\n', "\r\n");

    let lf_blocks = scanned(lf);
    let crlf_blocks = scanned(&crlf);
    assert_eq!(lf_blocks, crlf_blocks);

    let global = &lf_blocks[0];
    assert_eq!(global.name, "global");
    assert_eq!(global.line, 5);
    assert_eq!(global.header, "global {");
    assert_eq!(global.closing, "}");
    assert_eq!(global.items, vec![statement("log_level: debug", 6)]);
}

#[test]
fn quoted_braces_and_escaped_quotes_are_data() {
    let input = r#"global {
 single: 'a{b}c'
 double: "a}b{c"
 escaped_single: 'a\'b{c}'
 escaped_double: "a\"b}c"
 unterminated: bare'word{value}
 done: yes
}"#;
    let blocks = scanned(input);
    assert_eq!(blocks.len(), 1);
    assert_eq!(
        blocks[0].items,
        vec![
            statement("single: 'a{b}c'", 2),
            statement("double: \"a}b{c\"", 3),
            statement("escaped_single: 'a\\'b{c}'", 4),
            statement("escaped_double: \"a\\\"b}c\"", 5),
            statement("unterminated: bare'word{value}", 6),
            statement("done: yes", 7),
        ]
    );
    assert_eq!(blocks[0].closing, "}");
}

#[test]
fn quoted_end_skips_escaped_characters_and_rejects_unterminated_quotes() {
    assert_eq!(quoted_end(br#"'abc' trailing"#, 0), Some(5));
    assert_eq!(quoted_end(br#"'abc\'def'"#, 0), Some(10));
    assert_eq!(quoted_end(br#"x'abc' trailing"#, 1), Some(6));
    assert_eq!(quoted_end(br#""unterminated"#, 0), None);
}

#[test]
fn bare_values_function_data_and_uri_braces_remain_single_statements() {
    let input = "node {\n path: /tmp/{debug}.log\n matcher: name(a{2})\n uri: socks5://127.0.0.1:1080#a{b}\n}\n";
    let blocks = scanned(input);
    assert_eq!(blocks[0].name, "node");
    assert_eq!(
        blocks[0].items,
        vec![
            statement("path: /tmp/{debug}.log", 2),
            statement("matcher: name(a{2})", 3),
            statement("uri: socks5://127.0.0.1:1080#a{b}", 4),
        ]
    );
}

#[test]
fn line_final_names_keep_numeric_non_ascii_and_multiword_headers() {
    let input = "123 {\n value: numeric\n}\n香港 {\n value: unicode\n}\nHong Kong {\n value: multiword\n}\n";
    let blocks = scanned(input);
    assert_eq!(
        blocks
            .iter()
            .map(|block| (block.name.as_str(), block.line))
            .collect::<Vec<_>>(),
        vec![("123", 1), ("香港", 4), ("Hong Kong", 7)]
    );
    assert_eq!(blocks[0].items, vec![statement("value: numeric", 2)]);
    assert_eq!(blocks[1].items, vec![statement("value: unicode", 5)]);
    assert_eq!(blocks[2].items, vec![statement("value: multiword", 8)]);
}

#[test]
fn one_line_blocks_and_nested_blocks_keep_remainders_and_lines() {
    let input = "global { log_level: debug }\ngroup { g { policy: score } }\n";
    let blocks = scanned(input);
    assert_eq!(blocks.len(), 2);

    let global = &blocks[0];
    assert_eq!(global.line, 1);
    assert_eq!(global.header, "global {");
    assert_eq!(global.closing, "}");
    assert_eq!(global.items, vec![statement("log_level: debug", 1)]);

    let group = &blocks[1];
    assert_eq!(group.line, 2);
    assert_eq!(group.header, "group {");
    assert_eq!(group.closing, "}");
    assert_eq!(child_names(group), vec!["g"]);
    let Item::Block(child) = &group.items[0] else {
        panic!("expected nested named block");
    };
    assert_eq!(child.line, 2);
    assert_eq!(child.header, "g {");
    assert_eq!(child.closing, "}");
    assert_eq!(child.items, vec![statement("policy: score", 2)]);
}

#[test]
fn anonymous_brace_then_named_close_keeps_the_whole_value() {
    let input = "global {\n log_file: /tmp/{x}.log }\n";
    let blocks = scanned(input);
    assert_eq!(
        blocks[0].items,
        vec![statement("log_file: /tmp/{x}.log", 2)]
    );
    assert_eq!(blocks[0].closing, "}");
}

#[test]
fn closing_line_prefix_with_comment_is_a_statement_before_the_close() {
    let input = "global {\n log_file: /tmp/a } # note\n";
    let blocks = scanned(input);
    assert_eq!(blocks[0].items, vec![statement("log_file: /tmp/a", 2)]);
    assert_eq!(blocks[0].closing, "} # note");
}

#[test]
fn statement_before_nested_close_is_retained() {
    let input = "group {\n child {\n  policy: score }\n}\n";
    let blocks = scanned(input);
    let Item::Block(child) = &blocks[0].items[0] else {
        panic!("expected nested named block");
    };
    assert_eq!(child.items, vec![statement("policy: score", 3)]);
    assert_eq!(child.line, 2);
    assert_eq!(blocks[0].closing, "}");
}

#[test]
fn stray_close_is_dropped_and_reports_exact_diagnostic_fields() {
    let input = "global {\n log_level: debug\n}\n}\n";
    let (blocks, diagnostics) = scanned_with_diagnostics(input);
    assert_eq!(blocks[0].items, vec![statement("log_level: debug", 2)]);
    assert_eq!(
        diagnostics,
        vec![ConfigDiagnostic {
            setting: String::new(),
            value: "4".to_owned(),
            message: "unmatched `}` ignored".to_owned(),
        }]
    );
}

#[test]
fn scanner_reports_exact_unexpected_and_unclosed_errors() {
    assert_eq!(parse_error("{\n", None), "unexpected `{` at line 1");
    assert_eq!(
        parse_error("\n# comment\n {\n", None),
        "unexpected `{` at line 3"
    );
    assert_eq!(
        parse_error("global {\n", None),
        "unclosed block `global` opened at line 1"
    );
    assert_eq!(
        parse_error("global {\n", Some(Path::new("/tmp/settings.dae"))),
        "unclosed block `global` opened at line 1"
    );
}

#[test]
fn unclosed_include_uses_include_error_when_source_is_known() {
    let mut diagnostics = Vec::new();
    let error = scan(
        "include {\n proxy.dae\n",
        Some(Path::new("/tmp/settings.dae")),
        &mut diagnostics,
        &mut false,
    )
    .expect_err("unclosed include should fail");
    assert_eq!(
        error.to_string(),
        "Include error: unclosed include section in '/tmp/settings.dae'"
    );
    assert!(diagnostics.is_empty());
}

#[test]
fn include_header_comments_are_skipped_and_raw_body_is_preserved() {
    let input = "include # header comment\n# between header and brace\n{\nfoo.dae # trailing comment\n# comment containing }\n\"bar {file}.dae\"\n}\nglobal {\n log_level: debug\n}\n";
    let blocks = scanned(input);
    assert_eq!(blocks.len(), 2);
    let include = &blocks[0];
    assert_eq!(include.name, "include");
    assert_eq!(include.line, 1);
    assert_eq!(include.header, "include {");
    assert_eq!(include.closing, "}");
    assert_eq!(
        include.include_body.as_deref(),
        Some("\nfoo.dae # trailing comment\n# comment containing }\n\"bar {file}.dae\"\n")
    );
    assert_eq!(blocks[1].name, "global");
}

#[test]
fn projection_omits_recognised_blocks_and_recurses_unrecognised_blocks_in_source_order() {
    let input = "global {\n root: zero\n recognised {\n  hidden: one\n }\n unknown {\n  before: two\n  deep {\n   nested: three\n  }\n  after: four\n }\n tail: five\n}\n";
    let blocks = scanned(input);
    let global = &blocks[0];
    let Item::Block(recognised) = &global.items[1] else {
        panic!("expected recognised child block");
    };
    assert_eq!(recognised.line, 3);
    let Item::Block(unknown) = &global.items[2] else {
        panic!("expected unknown child block");
    };
    assert_eq!(unknown.line, 6);
    let Item::Block(deep) = &unknown.items[1] else {
        panic!("expected recursive child block");
    };
    assert_eq!(deep.line, 8);
    assert_eq!(child_names(global), vec!["recognised", "unknown"]);
    assert_eq!(
        projected(global, &["recognised"]),
        vec![
            "root: zero",
            "unknown {",
            "before: two",
            "deep {",
            "nested: three",
            "}",
            "after: four",
            "}",
            "tail: five",
        ]
    );
    assert_eq!(
        projected(global, &[]),
        vec![
            "root: zero",
            "recognised {",
            "hidden: one",
            "}",
            "unknown {",
            "before: two",
            "deep {",
            "nested: three",
            "}",
            "after: four",
            "}",
            "tail: five",
        ]
    );
}

#[test]
fn non_line_final_openers_with_comments_still_create_named_blocks() {
    let input = "global {\n child { # trailing header comment\n  value: yes\n }\n}\n";
    let blocks = scanned(input);
    let Item::Block(child) = &blocks[0].items[0] else {
        panic!("expected the non-line-final child header to open a block");
    };
    assert_eq!(child.name, "child");
    assert_eq!(child.line, 2);
    assert_eq!(child.header, "child {");
    assert_eq!(child.items, vec![statement("value: yes", 3)]);
    assert_eq!(child.closing, "}");
}

#[test]
fn anonymous_depth_can_span_lines_without_creating_a_child_block() {
    let input = "global {\n payload: /tmp/{ more\n  middle: value\n }\n tail: done\n}\n";
    let blocks = scanned(input);
    assert_eq!(child_names(&blocks[0]), Vec::<&str>::new());
    assert_eq!(
        blocks[0].items,
        vec![
            statement("payload: /tmp/{ more", 2),
            statement("middle: value", 3),
            statement("}", 4),
            statement("tail: done", 5),
        ]
    );
    assert_eq!(blocks[0].closing, "}");
}

#[test]
fn subscription_tag_blocks_and_double_colon_headers_are_scanned_without_parsing_values() {
    let input = "subscription {\n a: {\n  url: https://example.test\n  wrapper {\n   ignored: value\n  }\n  b: value\n }\n\n a: b: {\n  url: second\n }\n}\n";
    let blocks = scanned(input);
    let subscription = &blocks[0];
    assert_eq!(subscription.name, "subscription");
    assert_eq!(child_names(subscription), vec!["a:", "a: b:"]);
    let Item::Block(tag) = &subscription.items[0] else {
        panic!("expected subscription tag block");
    };
    assert_eq!(tag.name, "a:");
    assert_eq!(tag.line, 2);
    assert_eq!(child_names(tag), vec!["wrapper"]);
    assert_eq!(
        projected(tag, &[]),
        vec![
            "url: https://example.test",
            "wrapper {",
            "ignored: value",
            "}",
            "b: value",
        ]
    );
    let Item::Block(double_colon) = &subscription.items[1] else {
        panic!("expected the double-colon header to remain a named scanner block");
    };
    assert_eq!(double_colon.name, "a: b:");
    assert_eq!(double_colon.line, 10);
    assert_eq!(double_colon.items, vec![statement("url: second", 11)]);
}

#[test]
fn root_blocks_are_not_aggregated_and_direct_children_keep_source_order() {
    let input =
        "global {\n first: one\n}\ngroup {\n a {\n }\n b {\n }\n}\n\nglobal {\n second: two\n}\n";
    let blocks = scanned(input);
    assert_eq!(
        blocks
            .iter()
            .map(|block| (block.name.as_str(), block.line))
            .collect::<Vec<_>>(),
        vec![("global", 1), ("group", 4), ("global", 11)]
    );
    assert_eq!(child_names(&blocks[1]), vec!["a", "b"]);
    assert_eq!(blocks[0].items, vec![statement("first: one", 2)]);
    assert_eq!(blocks[2].items, vec![statement("second: two", 12)]);
}

#[test]
fn projection_preserves_header_spacing_and_closing_comments() {
    let blocks = scanned("global {\n unknown\t{\n value: yes\n } # close\n}\n");
    assert_eq!(
        projected(&blocks[0], &[]),
        ["unknown\t{", "value: yes", "} # close"]
    );
}

#[test]
fn unicode_headers_do_not_require_ascii_byte_boundaries() {
    let blocks = scanned("香港节点 {\n policy: score\n}\n");
    assert_eq!(blocks[0].name, "香港节点");
    assert_eq!(blocks[0].line, 1);
    assert_eq!(blocks[0].items, [statement("policy: score", 2)]);
}

#[test]
fn include_mode_resumes_after_another_block_on_the_same_line() {
    let blocks = scanned("global {} include { 'a{b}.dae' # }\n next.dae\n} routing {}");
    assert_eq!(
        blocks
            .iter()
            .map(|block| block.name.as_str())
            .collect::<Vec<_>>(),
        ["global", "include", "routing"]
    );
    assert_eq!(blocks[1].line, 1);
    assert_eq!(
        blocks[1].include_body.as_deref(),
        Some(" 'a{b}.dae' # }\n next.dae\n")
    );
    assert_eq!(blocks[2].line, 3);
}

#[test]
fn include_quotes_do_not_recover_as_ordinary_characters() {
    let error = scan(
        "include { 'unterminated.dae }",
        Some(Path::new("entry.dae")),
        &mut Vec::new(),
        &mut false,
    )
    .unwrap_err();
    assert!(matches!(error, ConfigError::Include(message)
        if message == "unclosed include section in 'entry.dae'"));
}

#[test]
fn subscription_inline_tags_may_touch_their_opening_brace() {
    let blocks = scanned("subscription { 'my tag':{ url: 'http://example.test' } }");
    let tag = blocks[0].blocks_any().next().unwrap();
    assert_eq!(tag.header, "'my tag':{");
    assert_eq!(tag.items, [statement("url: 'http://example.test'", 1)]);
}

#[test]
fn comments_after_named_boundaries_do_not_count_braces() {
    let blocks = scanned("group { # }\n g { # {\n policy: score\n } # }\n}\n");
    let group = blocks[0].blocks_any().next().unwrap();
    assert_eq!(group.name, "g");
    assert_eq!(group.line, 2);
    assert_eq!(group.items, [statement("policy: score", 3)]);
}
