use std::fs;

use honk_config::routing::RoutingOutbound;
use honk_config::{Config, ConfigError};

fn write(path: &std::path::Path, content: &str) {
    fs::write(path, content)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}

#[test]
fn include_loads_nested_globs_and_merges_sections() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("config files")).unwrap();
    fs::create_dir_all(root.join("config.d")).unwrap();
    fs::create_dir_all(root.join("fragments")).unwrap();

    let absolute = root.join("absolute.dae");
    write(
        &root.join("config files/base config.dae"),
        r#"
include {
    fragments/nested.dae
}

global {
    log_level: info
}

node {
    base: 'socks5://127.0.0.1:1080'
}
"#,
    );
    write(
        &root.join("fragments/nested.dae"),
        r#"
group {
    proxy {
        filter: name('base')
        policy: select
    }
}
"#,
    );
    write(
        &absolute,
        r#"
node {
    absolute: 'socks5://127.0.0.1:1081'
}
"#,
    );
    write(
        &root.join("config.d/10-dns.dae"),
        r#"
dns {
    ipversion_prefer: 4
    upstream {
        first: 'udp://1.1.1.1:53'
    }
    routing {
        request {
            qtype(a) -> first
            fallback: first
        }
    }
}
"#,
    );
    write(
        &root.join("config.d/20-routes.dae"),
        r#"
global {
    log_level: debug
}

node {
    extra: 'socks5://127.0.0.1:1082'
}

routing {
    dport(443) -> proxy
    fallback: proxy
}

dns {
    upstream {
        second: 'udp://8.8.8.8:53'
    }
    routing {
        request {
            qtype(aaaa) -> second
            fallback: second
        }
    }
    ipversion_prefer: 6
}
"#,
    );
    write(&root.join("ignored.txt"), "this is not dae syntax");

    write(
        &root.join("config.dae"),
        &format!(
            r#"
include {{ 'config files/base config.dae' '{}' config.d/*.dae missing/*.dae ignored.txt }}

global {{
    tproxy_port: 32123
    log_level: warn
}}

routing {{
    dport(80) -> direct
}}
"#,
            absolute.display()
        ),
    );

    let config = Config::from_file(root.join("config.dae").to_str().unwrap()).unwrap();

    // The root is merged first, then each include in declaration and glob
    // order.  A later scalar changes only that key, rather than resetting the
    // rest of global.
    assert_eq!(config.global.tproxy_port, 32123);
    assert_eq!(config.global.log_level, "debug");
    assert_eq!(
        config
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        vec!["base", "absolute", "extra"]
    );

    let group = config
        .groups
        .iter()
        .find(|group| group.name == "proxy")
        .unwrap();
    let base = config
        .nodes
        .iter()
        .find(|node| node.name == "base")
        .unwrap();
    assert_eq!(group.nodes, vec![base.id]);

    assert_eq!(
        config
            .routing
            .rules
            .iter()
            .map(|rule| match &rule.outbound {
                RoutingOutbound::Simple(name) => name.as_str(),
                RoutingOutbound::Complex { .. } => panic!("expected a simple outbound"),
            })
            .collect::<Vec<_>>(),
        vec!["direct", "proxy"]
    );
    assert_eq!(config.routing.default_outbound, "proxy");
    assert_eq!(
        config
            .dns
            .upstream
            .iter()
            .map(|upstream| upstream.name.as_str())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );
    assert_eq!(config.dns.routing.request.rules.len(), 2);
    assert_eq!(config.dns.routing.fallback, "second");
    assert!(matches!(
        config.dns.strategy,
        honk_config::dns::DnsStrategy::PreferIpv6
    ));
}

#[test]
fn include_rejects_cycles_and_paths_outside_the_entry_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();

    write(
        &dir.path().join("outside.dae"),
        "global {\n    log_level: info\n}\n",
    );
    write(
        &root.join("escape.dae"),
        "include { ../outside.dae }\nglobal {\n}\n",
    );
    let err = Config::from_file(root.join("escape.dae").to_str().unwrap()).unwrap_err();
    assert!(matches!(err, ConfigError::Include(_)));
    assert!(
        err.to_string()
            .contains("outside entry configuration directory")
    );

    write(
        &root.join("config.dae"),
        "include { child.dae }\nglobal {\n}\n",
    );
    write(
        &root.join("child.dae"),
        "include { config.dae }\nnode {\n}\n",
    );
    let err = Config::from_file(root.join("config.dae").to_str().unwrap()).unwrap_err();
    assert!(matches!(err, ConfigError::Include(_)));
    assert!(err.to_string().contains("circular or duplicate include"));
}

#[cfg(unix)]
#[test]
fn include_rejects_symlinks_that_escape_the_entry_directory() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let outside = dir.path().join("outside.dae");
    write(&outside, "global {\n    log_level: info\n}\n");
    symlink(&outside, root.join("linked.dae")).unwrap();
    write(
        &root.join("config.dae"),
        "include { linked.dae }\nglobal {\n}\n",
    );

    let err = Config::from_file(root.join("config.dae").to_str().unwrap()).unwrap_err();
    assert!(matches!(err, ConfigError::Include(_)));
    assert!(
        err.to_string()
            .contains("outside entry configuration directory")
    );
}
