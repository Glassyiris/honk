//! CLI tests for `honk-tool geosite` / `honk-tool geoip` against small
//! synthetic dat fixtures (the wire encoder mirrors the v2ray/dae dat
//! protobuf layout).

use std::path::Path;
use std::process::Command;

fn push_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn push_field(tag: u32, wire: u8, out: &mut Vec<u8>) {
    push_varint(((tag as u64) << 3) | wire as u64, out);
}

fn push_len_delim(tag: u32, payload: &[u8], out: &mut Vec<u8>) {
    push_field(tag, 2, out);
    push_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn push_varint_field(tag: u32, v: u64, out: &mut Vec<u8>) {
    push_field(tag, 0, out);
    push_varint(v, out);
}

fn domain_msg(dtype: i32, value: &str, attrs: &[&str]) -> Vec<u8> {
    let mut m = Vec::new();
    push_varint_field(1, dtype as u64, &mut m);
    push_len_delim(2, value.as_bytes(), &mut m);
    for key in attrs {
        let mut a = Vec::new();
        push_len_delim(1, key.as_bytes(), &mut a);
        push_len_delim(3, &a, &mut m);
    }
    m
}

fn geosite_fixture() -> Vec<u8> {
    let mut dat = Vec::new();
    let entries = [
        (
            "TEST-CORE",
            vec![
                domain_msg(2, "example.com", &["cn"]),
                domain_msg(3, "exact.test", &[]),
                domain_msg(0, "tracker", &[]),
                domain_msg(1, "^ads-[0-9]+\\.test$", &[]),
            ],
        ),
        ("TEST-EXTRA", vec![domain_msg(2, "extra.com", &[])]),
    ];
    for (code, domains) in entries {
        let mut e = Vec::new();
        push_len_delim(1, code.as_bytes(), &mut e);
        for d in domains {
            push_len_delim(2, &d, &mut e);
        }
        push_len_delim(1, &e, &mut dat);
    }
    dat
}

fn geoip_fixture() -> Vec<u8> {
    type CidrSpec<'a> = (&'a [u8], u32);
    let mut dat = Vec::new();
    let entries: [(&str, Vec<CidrSpec>); 2] = [
        ("TEST", vec![(&[10, 0, 0, 0], 8), (&[10, 9, 0, 0], 16)]),
        ("OTHER", vec![(&[192, 168, 0, 0], 16)]),
    ];
    for (code, cidrs) in entries {
        let mut e = Vec::new();
        push_len_delim(1, code.as_bytes(), &mut e);
        for (ip, prefix) in cidrs {
            let mut c = Vec::new();
            push_len_delim(1, ip, &mut c);
            push_varint_field(2, u64::from(prefix), &mut c);
            push_len_delim(2, &c, &mut e);
        }
        push_len_delim(1, &e, &mut dat);
    }
    dat
}

struct Fixture {
    _dir: tempfile::TempDir,
    geosite: std::path::PathBuf,
    geoip: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let geosite = dir.path().join("geosite.dat");
        let geoip = dir.path().join("geoip.dat");
        std::fs::write(&geosite, geosite_fixture()).unwrap();
        std::fs::write(&geoip, geoip_fixture()).unwrap();
        Self {
            _dir: dir,
            geosite,
            geoip,
        }
    }
}

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_honk-tool"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn file_arg(path: &Path) -> String {
    format!("--file={}", path.display())
}

#[test]
fn geosite_list_and_filter() {
    let fx = Fixture::new();
    let file = file_arg(&fx.geosite);

    let (ok, stdout, _) = run(&["geosite", "list", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST-CORE 4\nTEST-EXTRA 1\n");

    let (ok, stdout, _) = run(&["geosite", "list", "core", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST-CORE 4\n");
}

#[test]
fn geosite_show_with_attr_filter() {
    let fx = Fixture::new();
    let file = file_arg(&fx.geosite);

    let (ok, stdout, _) = run(&["geosite", "show", "test-core", &file]);
    assert!(ok);
    assert_eq!(
        stdout,
        "TEST-CORE domain example.com @cn\n\
         TEST-CORE full exact.test\n\
         TEST-CORE keyword tracker\n\
         TEST-CORE regexp ^ads-[0-9]+\\.test$\n"
    );

    let (ok, stdout, _) = run(&["geosite", "show", "TEST-CORE", "--attr", "cn", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST-CORE domain example.com @cn\n");

    let (ok, _, stderr) = run(&["geosite", "show", "NOPE", &file]);
    assert!(!ok);
    assert!(stderr.contains("not found"), "stderr: {stderr}");
}

#[test]
fn geosite_find_reverse_lookup() {
    let fx = Fixture::new();
    let file = file_arg(&fx.geosite);

    // suffix entry
    let (ok, stdout, _) = run(&["geosite", "find", "www.example.com", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST-CORE domain example.com @cn\n");

    // keyword + regex entries both count
    let (ok, stdout, _) = run(&["geosite", "find", "x-tracker-x", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST-CORE keyword tracker\n");
    let (ok, stdout, _) = run(&["geosite", "find", "ads-7.test", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST-CORE regexp ^ads-[0-9]+\\.test$\n");

    // no match
    let (ok, stdout, _) = run(&["geosite", "find", "unrelated.net", &file]);
    assert!(ok);
    assert_eq!(stdout, "");
}

#[test]
fn geoip_list_show_lookup() {
    let fx = Fixture::new();
    let file = file_arg(&fx.geoip);

    let (ok, stdout, _) = run(&["geoip", "list", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST 2\nOTHER 1\n");

    let (ok, stdout, _) = run(&["geoip", "show", "test", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST 10.0.0.0/8\nTEST 10.9.0.0/16\n");

    // longest prefix wins over the /8
    let (ok, stdout, _) = run(&["geoip", "lookup", "10.9.1.1", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST 10.9.0.0/16\n");

    let (ok, stdout, _) = run(&["geoip", "lookup", "10.8.1.1", &file]);
    assert!(ok);
    assert_eq!(stdout, "TEST 10.0.0.0/8\n");

    let (ok, stdout, _) = run(&["geoip", "lookup", "8.8.8.8", &file]);
    assert!(ok);
    assert_eq!(stdout, "");
}

#[test]
fn missing_file_errors_with_hint() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.dat");
    let (ok, _, stderr) = run(&["geoip", "list", &file_arg(&missing)]);
    assert!(!ok);
    assert!(stderr.contains("no such file"), "stderr: {stderr}");
}
