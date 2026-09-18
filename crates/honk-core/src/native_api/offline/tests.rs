use super::*;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt as _;

fn fixture(directory: &Path, extra: &str) -> LoadedConfig {
    let path = directory.join("config.dae");
    let text = format!(
        "global {{ data_dir: '{}'\n nfqueue_enable: false\n dial_mode: ip }}\nrouting {{ fallback: direct }}\n{extra}",
        directory.join("state").display(),
    );
    fs::write(&path, text).unwrap();
    Config::from_dae_file_with_sources(
        &path,
        &HashMap::new(),
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
}

fn admit(loaded: LoadedConfig, active: &Config) -> Result<ValidatedConfig, DetailedConfigError> {
    admit_with_limits(loaded, active, SourceLimits::default())
}

fn admit_with_limits(
    loaded: LoadedConfig,
    active: &Config,
    limits: SourceLimits,
) -> Result<ValidatedConfig, DetailedConfigError> {
    validate_with_data_dir(
        loaded,
        active,
        Path::new(&active.global.data_dir),
        limits,
        &mut Vec::new(),
    )
}

#[test]
fn effective_root_overrides_requested_data_directory() {
    let temp = tempfile::tempdir().unwrap();
    let effective = tempfile::tempdir().unwrap();
    let loaded = fixture(temp.path(), "dns { use_host: 'hosts.rules' }");
    let active = loaded.config.clone();
    let requested = Path::new(&active.global.data_dir);
    fs::create_dir(requested).unwrap();
    fs::write(
        requested.join("hosts.rules"),
        "full:requested.test 192.0.2.1\n",
    )
    .unwrap();
    let selected = effective.path().join("hosts.rules");
    fs::write(&selected, "full:effective.test 192.0.2.2\n").unwrap();
    let result = validate_with_data_dir(
        loaded,
        &active,
        effective.path(),
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        result.dependencies[0].path,
        fs::canonicalize(selected).unwrap()
    );
}

#[test]
fn offline_admission_does_not_create_runtime_state_or_connect() {
    let temp = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut loaded = fixture(temp.path(), "");
    let active = loaded.config.clone();
    let sources = loaded.sources.clone();
    let admitted = admit(loaded.clone(), &active).unwrap();
    assert!(
        admitted
            .config
            .nodes
            .iter()
            .any(|node| node.name == "direct")
    );
    assert!(admitted.dependencies.is_empty());
    assert!(!temp.path().join("state").exists());
    loaded
        .config
        .subscriptions
        .push(honk_config::subscription::Subscription {
            name: "offline".into(),
            url: format!(
                "http://{}/private-credential",
                listener.local_addr().unwrap()
            ),
            ..Default::default()
        });
    let error = admit(loaded, &active).err().unwrap();
    assert_eq!(error.diagnostic.code, "missing-offline-dependency");
    assert!(!format!("{error:?}").contains("private-credential"));
    assert!(!temp.path().join("state").exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        fs::read_to_string(&sources[0].path).unwrap(),
        sources[0].content.as_ref()
    );
}

#[test]
fn hosts_admission_charges_each_materialized_reference() {
    let temp = tempfile::tempdir().unwrap();
    let hosts = temp.path().join("hosts.rules");
    let body = "full:exact.test 192.0.2.1\n";
    fs::write(&hosts, body).unwrap();
    let loaded = fixture(
        temp.path(),
        &format!(
            "dns {{ use_host: '{}'\n use_host: '{}/./hosts.rules' }}",
            hosts.display(),
            temp.path().display()
        ),
    );
    let active = loaded.config.clone();
    let size = loaded
        .sources
        .iter()
        .map(|source| source.content.len())
        .sum::<usize>()
        + 2 * body.len();
    let exact = SourceLimits {
        max_bytes: size,
        max_sources: 3,
    };
    let admitted = admit_with_limits(loaded.clone(), &active, exact).unwrap();
    assert_eq!(
        admitted.dependencies,
        vec![DependencySnapshot {
            path: fs::canonicalize(&hosts).unwrap(),
            bytes: body.len(),
            sha256: crate::native_api::config::digest(body.as_bytes()),
        }]
    );
    let short = SourceLimits {
        max_bytes: size - 1,
        ..exact
    };
    assert_eq!(
        admit_with_limits(loaded.clone(), &active, short)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "config-byte-limit"
    );
    let short = SourceLimits {
        max_sources: 2,
        ..exact
    };
    assert_eq!(
        admit_with_limits(loaded.clone(), &active, short)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "config-source-limit"
    );
    fs::write(&hosts, "regexp:[ 192.0.2.1\n").unwrap();
    let error = admit(loaded.clone(), &active).err().unwrap();
    assert_eq!(error.diagnostic.code, "invalid-offline-dependency");
    fs::remove_file(&hosts).unwrap();
    assert_eq!(
        admit(loaded, &active).err().unwrap().diagnostic.code,
        "missing-offline-dependency"
    );
}

#[test]
fn repeated_aliases_cannot_retain_bodies_beyond_byte_or_source_limits() {
    let temp = tempfile::tempdir().unwrap();
    let body = "full:alias.test 192.0.2.1\n";
    fs::write(temp.path().join("hosts.rules"), body).unwrap();
    let mut loaded = fixture(temp.path(), "");
    loaded.config.dns.hosts = (0..200)
        .map(|index| {
            format!(
                "{}/{}hosts.rules",
                temp.path().display(),
                "./".repeat(index)
            )
        })
        .collect();
    let source_bytes = loaded
        .sources
        .iter()
        .map(|source| source.content.len())
        .sum::<usize>();
    for (limits, expected_kind, retained_count) in [
        (
            SourceLimits {
                max_bytes: source_bytes + 3 * body.len(),
                max_sources: 32,
            },
            io::ErrorKind::FileTooLarge,
            3,
        ),
        (
            SourceLimits {
                max_bytes: source_bytes + 200 * body.len(),
                max_sources: 3,
            },
            io::ErrorKind::QuotaExceeded,
            2,
        ),
    ] {
        let mut capture = Capture::new(
            &loaded.sources,
            &loaded.config,
            Path::new(&loaded.config.global.data_dir),
            limits,
        )
        .unwrap();
        let mut retained_bytes = 0;
        let result = HostsSourceSet::load_captured(&loaded.config.dns, |path| {
            let text = capture.text(path)?;
            retained_bytes += text.len();
            Ok::<_, io::Error>(text)
        });
        assert_eq!(result.err().unwrap().kind(), expected_kind);
        assert_eq!(retained_bytes, retained_count * body.len());
        assert!(retained_bytes <= limits.max_bytes - source_bytes);
    }
}

#[test]
fn external_hosts_require_active_authorization_including_symlink_targets() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let external = outside.path().join("private.rules");
    fs::write(&external, "full:private.test 192.0.2.2\n").unwrap();
    let alias = temp.path().join("inside.rules");
    std::os::unix::fs::symlink(&external, &alias).unwrap();
    let loaded = fixture(
        temp.path(),
        &format!("dns {{ use_host: '{}' }}", alias.display()),
    );
    let mut active = loaded.config.clone();
    active.dns.hosts.clear();
    let error = admit(loaded.clone(), &active).err().unwrap();
    assert_eq!(error.diagnostic.code, "offline-dependency-denied");
    assert!(!error.to_string().contains("private.rules"));
    assert!(error.diagnostic.span.is_none());
    active
        .dns
        .hosts
        .push(external.to_string_lossy().into_owned());
    let admitted = admit(loaded, &active).unwrap();
    assert_eq!(
        admitted.dependencies[0].path,
        fs::canonicalize(external).unwrap()
    );
}

#[test]
fn ech_is_bounded_and_inline_material_wins_without_opening_a_file() {
    let temp = tempfile::tempdir().unwrap();
    let mut loaded = fixture(
        temp.path(),
        "node { tls: 'trojan://credential@127.0.0.1:443#tls' }",
    );
    let ech = temp.path().join("private.ech");
    let tls = loaded.config.nodes[0].tls_mut().unwrap();
    tls.ech_config_path = Some(ech.to_string_lossy().into_owned());
    loaded.config.nodes[0].id = loaded.config.nodes[0].derive_id();
    let active = loaded.config.clone();
    assert_eq!(
        admit(loaded.clone(), &active)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "missing-offline-dependency"
    );
    fs::write(&ech, "not base64!!").unwrap();
    let error = admit(loaded.clone(), &active).err().unwrap();
    assert_eq!(error.diagnostic.code, "invalid-tls-config");
    assert!(!error.to_string().contains("credential"));
    assert!(!error.to_string().contains("private.ech"));
    fs::write(&ech, "AA==\n").unwrap();
    let admitted = admit(loaded.clone(), &active).unwrap();
    assert_eq!(admitted.dependencies[0].bytes, 5);
    fs::remove_file(&ech).unwrap();
    loaded.config.nodes[0].tls_mut().unwrap().ech_config = Some("AA==".into());
    loaded.config.nodes[0].id = loaded.config.nodes[0].derive_id();
    assert!(admit(loaded, &active).unwrap().dependencies.is_empty());
}

fn cache_body(
    data_dir: &Path,
    subscription: &honk_config::subscription::Subscription,
    body: &str,
) -> PathBuf {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    let root = data_dir.join(".sub");
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let mut hash = Sha256::new();
    for value in [
        subscription.url.as_str(),
        subscription.user_agent.as_deref().unwrap_or_default(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    for header in &subscription.headers {
        for value in [&header.key, &header.value] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
    }
    let path = root.join(format!(
        "{}.sub",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.finalize())
    ));
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    path
}

#[test]
fn cached_presence_and_rebased_active_semantics_are_both_required() {
    let temp = tempfile::tempdir().unwrap();
    let mut loaded = fixture(temp.path(), "");
    let subscription = honk_config::subscription::Subscription {
        name: "provider".into(),
        url: "https://example.invalid/private-token".into(),
        ..Default::default()
    };
    loaded.config.subscriptions.push(subscription.clone());
    let mut active = loaded.config.clone();
    active.nodes = parse_subscription_content_with_diagnostics(
        &subscription,
        "trojan://password@127.0.0.1:443#active",
        &mut Vec::new(),
    )
    .unwrap();
    active.nodes[0].tls_mut().unwrap().pin_sha256 = Some("invalid-pin".into());
    active.nodes[0].id = active.nodes[0].derive_id();
    let cache = cache_body(
        Path::new(&active.global.data_dir),
        &subscription,
        "socks5://127.0.0.1:1080#cached",
    );
    let cached_only = admit(loaded.clone(), &loaded.config).unwrap();
    assert!(
        cached_only
            .config
            .nodes
            .iter()
            .any(|node| node.name == "cached")
    );
    assert_eq!(
        admit(loaded.clone(), &active)
            .err()
            .unwrap()
            .diagnostic
            .code,
        "invalid-tls-config"
    );
    active.nodes[0].tls_mut().unwrap().pin_sha256 = None;
    active.nodes[0].id = active.nodes[0].derive_id();
    let admitted = admit(loaded.clone(), &active).unwrap();
    assert!(
        admitted
            .config
            .nodes
            .iter()
            .any(|node| node.name == "active")
    );
    assert!(
        !admitted
            .config
            .nodes
            .iter()
            .any(|node| node.name == "cached")
    );
    assert_eq!(
        admitted.dependencies[0].path,
        fs::canonicalize(&cache).unwrap()
    );
    assert_eq!(
        fs::metadata(cache.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    assert_eq!(
        fs::metadata(&cache).unwrap().permissions().mode() & 0o7777,
        0o400
    );
    fs::remove_file(cache).unwrap();
    assert_eq!(
        admit(loaded, &active).err().unwrap().diagnostic.code,
        "missing-offline-dependency"
    );
}

#[test]
fn revalidation_detects_a_new_higher_priority_dependency() {
    let working = std::env::current_dir().unwrap();
    let temp = tempfile::tempdir_in(&working).unwrap();
    let mut loaded = fixture(temp.path(), "");
    let data_dir = PathBuf::from(&loaded.config.global.data_dir);
    fs::create_dir(&data_dir).unwrap();
    let lower = temp.path().join("hosts.rules");
    fs::write(&lower, "full:old.test 192.0.2.1\n").unwrap();
    let relative = lower.strip_prefix(&working).unwrap();
    let higher = data_dir.join(relative);
    loaded
        .config
        .dns
        .hosts
        .push(relative.to_string_lossy().into_owned());
    let active = loaded.config.clone();
    let old = admit(loaded.clone(), &active).unwrap();
    fs::create_dir_all(higher.parent().unwrap()).unwrap();
    fs::write(&higher, "full:new.test 192.0.2.2\n").unwrap();
    let new = admit(loaded, &active).unwrap();
    assert_ne!(old.dependencies, new.dependencies);
    assert_eq!(new.dependencies[0].path, fs::canonicalize(higher).unwrap());
}
