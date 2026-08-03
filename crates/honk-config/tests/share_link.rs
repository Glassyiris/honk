//! Integration tests for the unified share-link parser and the
//! extension-aware config (de)serialization.

use base64::Engine as _;
use honk_config::Config;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;

/// URL-safe base64 without padding (the encoding used by vmess links).
fn b64(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
}

#[test]
fn test_ss_base64_userinfo() {
    // SIP002: base64("aes-256-gcm:pass") as the whole userinfo.
    let node = Node::from_share_link("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss-b64").unwrap();
    assert_eq!(node.protocol, NodeProtocol::SS);
    assert_eq!(node.name, "ss-b64");
    assert_eq!(node.host, "1.2.3.4");
    assert_eq!(node.port, 8388);
    assert_eq!(node.encryption.as_deref(), Some("aes-256-gcm"));
    assert_eq!(node.password.as_deref(), Some("pass"));
    assert!(node.username.is_none());
}

#[test]
fn test_ss_base64_userinfo_with_padding_and_plugin_suffix() {
    // Same but padded base64 and the `/?plugin=...` suffix form.
    let node = Node::from_share_link(
        "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388/?plugin=v2ray-plugin%3Btls#ss-pad",
    )
    .unwrap();
    assert_eq!(node.encryption.as_deref(), Some("aes-256-gcm"));
    assert_eq!(node.password.as_deref(), Some("pass"));
    assert_eq!(node.plugin.as_deref(), Some("v2ray-plugin"));
    assert_eq!(node.plugin_opts.as_deref(), Some("tls"));
}

#[test]
fn test_ss_plain_userinfo() {
    let node = Node::from_share_link("ss://aes-256-gcm:mypassword@2.3.4.5:8389#ss-plain").unwrap();
    assert_eq!(node.protocol, NodeProtocol::SS);
    assert_eq!(node.encryption.as_deref(), Some("aes-256-gcm"));
    assert_eq!(node.password.as_deref(), Some("mypassword"));
    assert!(node.username.is_none());
}

#[test]
fn test_ss_plain_userinfo_base64_method() {
    // Plain userinfo whose method part is base64("chacha20-ietf-poly1305").
    let node =
        Node::from_share_link("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNQ:mypassword@2.3.4.5:8389#ss-bm")
            .unwrap();
    assert_eq!(node.encryption.as_deref(), Some("chacha20-ietf-poly1305"));
    assert_eq!(node.password.as_deref(), Some("mypassword"));
}

#[test]
fn test_ss_with_plugin() {
    let node = Node::from_share_link(
        "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#ss-plugin",
    )
    .unwrap();
    assert_eq!(node.protocol, NodeProtocol::SS);
    assert_eq!(node.encryption.as_deref(), Some("aes-256-gcm"));
    assert_eq!(node.plugin.as_deref(), Some("obfs-local"));
    assert_eq!(
        node.plugin_opts.as_deref(),
        Some("obfs=http;obfs-host=example.com")
    );
}

#[test]
fn test_trojan_ws_query() {
    let node = Node::from_share_link(
        "trojan://pw@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=sni.example.com#trojan-ws",
    )
    .unwrap();
    assert_eq!(node.protocol, NodeProtocol::Trojan);
    assert_eq!(node.name, "trojan-ws");
    assert!(node.tls);
    assert_eq!(node.password.as_deref(), Some("pw"));
    assert_eq!(node.transport, "ws");
    assert_eq!(node.ws_path.as_deref(), Some("/ws"));
    assert_eq!(node.ws_host.as_deref(), Some("cdn.example.com"));
    assert_eq!(node.sni.as_deref(), Some("sni.example.com"));
}

#[test]
fn test_anytls_pool_query() {
    let node = Node::from_share_link(
        "anytls://uuid-pw@any.example.com:443?insecure=1&sni=any.example.com&idle_session_check_interval=30s&idle_session_timeout=1m&min_idle_session=4#anytls-node",
    )
    .unwrap();
    assert_eq!(node.protocol, NodeProtocol::AnyTLS);
    assert!(node.tls);
    assert!(node.skip_cert_verify);
    assert_eq!(node.sni.as_deref(), Some("any.example.com"));
    assert_eq!(node.password.as_deref(), Some("uuid-pw"));
    assert_eq!(node.anytls_password.as_deref(), Some("uuid-pw"));
    assert_eq!(node.anytls_idle_session_check_interval, Some(30));
    assert_eq!(node.anytls_idle_session_timeout, Some(60));
    assert_eq!(node.anytls_min_idle_session, Some(4));
}

#[test]
fn test_vmess_full_fields_ws_tls() {
    // v2rayN-style base64(JSON) with the full WS+TLS field set.
    let json = r#"{
        "v": "2",
        "ps": "vmess-ws-tls",
        "add": "vmess.example.com",
        "port": "443",
        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/vmess-ws",
        "tls": "tls",
        "sni": "sni.example.com",
        "alpn": "h2,http/1.1"
    }"#;
    let node = Node::from_share_link(&format!("vmess://{}", b64(json))).unwrap();
    assert_eq!(node.protocol, NodeProtocol::VMess);
    assert_eq!(node.name, "vmess-ws-tls");
    assert_eq!(node.host, "vmess.example.com");
    assert_eq!(node.address, "vmess.example.com:443");
    assert_eq!(node.port, 443);
    assert_eq!(
        node.password.as_deref(),
        Some("b831381d-6324-4d53-ad4f-8cda48b30811")
    );
    assert_eq!(node.encryption.as_deref(), Some("auto"));
    assert_eq!(node.transport, "ws");
    assert_eq!(node.network.as_deref(), Some("ws"));
    assert!(node.tls);
    assert_eq!(node.ws_host.as_deref(), Some("cdn.example.com"));
    assert_eq!(node.ws_path.as_deref(), Some("/vmess-ws"));
    assert_eq!(node.sni.as_deref(), Some("sni.example.com"));
}

#[test]
fn test_vmess_standard_base64_and_numeric_port() {
    // STANDARD base64 alphabet with padding and a numeric JSON port.
    let json = r#"{"add":"1.2.3.4","port":8388,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"tcp","tls":"","security":"aes-128-gcm"}"#;
    let encoded = base64::engine::general_purpose::STANDARD.encode(json);
    let node = Node::from_share_link(&format!("vmess://{}", encoded)).unwrap();
    assert_eq!(node.protocol, NodeProtocol::VMess);
    assert_eq!(node.host, "1.2.3.4");
    assert_eq!(node.port, 8388);
    assert_eq!(node.transport, "tcp");
    assert!(!node.tls);
    // `security` is the older cipher key, picked up when `scy` is absent.
    assert_eq!(node.encryption.as_deref(), Some("aes-128-gcm"));
    // No remark: the name falls back to `vmess-<host>` (never the raw link,
    // which would leak the user id).
    assert_eq!(node.name, "vmess-1.2.3.4");
}

#[test]
fn test_vmess_grpc_service_from_path() {
    // On grpc links the JSON `path` carries the gRPC service name and
    // `host` falls back to the TLS SNI.
    let json = r#"{"ps":"vmess-grpc","add":"g.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"grpc","path":"MyService","host":"sni.example.com","tls":"tls"}"#;
    let node = Node::from_share_link(&format!("vmess://{}", b64(json))).unwrap();
    assert_eq!(node.transport, "grpc");
    assert_eq!(node.grpc_service.as_deref(), Some("MyService"));
    assert!(node.ws_path.is_none());
    assert!(node.ws_host.is_none());
    assert_eq!(node.sni.as_deref(), Some("sni.example.com"));
    assert!(node.tls);
}

#[test]
fn test_vmess_invalid_links_rejected() {
    assert!(Node::from_share_link("vmess://!!!not-base64!!!").is_err());
    // Valid base64 but not JSON.
    assert!(Node::from_share_link(&format!("vmess://{}", b64("not json"))).is_err());
    // JSON without a server address.
    assert!(
        Node::from_share_link(&format!("vmess://{}", b64(r#"{"port":443,"id":"x"}"#))).is_err()
    );
}

#[test]
fn test_removed_protocol_links_rejected() {
    // ssr/trojan-go/http(s) support was removed; the links now fail as
    // unknown protocols (hard error in config files, skipped with a
    // warning in subscriptions).
    let ssr_link = format!("ssr://{}", b64("example.com:443:origin:none:plain:cHc"));
    for link in [
        ssr_link.as_str(),
        "trojan-go://pw@example.com:443",
        "http://proxy.example.com:8080",
        "https://user:pass@proxy.example.com:8443",
    ] {
        let err = Node::from_share_link(link).unwrap_err();
        assert!(
            err.to_string().contains("Unknown node protocol"),
            "'{link}' must be rejected: {err}"
        );
    }
}

#[test]
fn test_unknown_scheme_rejected() {
    let err = Node::from_share_link("unknown://host:1234").unwrap_err();
    assert!(err.to_string().contains("Unknown node protocol"));
}

/// Build a config holding an experimental section and three fully populated
/// nodes (ss, trojan+ws, anytls) for serialization round-trip tests.
fn sample_config() -> Config {
    let mut config = Config::default();
    config.experimental.clash_api.external_controller = "0.0.0.0:9999".to_string();
    config.experimental.clash_api.external_ui = "yacd".to_string();
    config.experimental.clash_api.secret = "s3cret".to_string();
    config.experimental.cache_file.enabled = true;
    config.experimental.cache_file.path = "cache.db".to_string();
    config.experimental.cache_file.cache_id = "router1".to_string();
    config.experimental.cache_file.store_fakeip = true;

    config.nodes.push(
        Node::from_share_link(
            "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp#ss-node",
        )
        .unwrap(),
    );
    config.nodes.push(
        Node::from_share_link(
            "trojan://pw@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=sni.example.com#trojan-node",
        )
        .unwrap(),
    );
    config.nodes.push(
        Node::from_share_link(
            "anytls://uuid-pw@any.example.com:443?insecure=1&idle_session_timeout=1m&min_idle_session=4#anytls-node",
        )
        .unwrap(),
    );
    config
}

#[test]
fn test_config_json_round_trip() {
    let config = sample_config();
    let json = config.to_json_string().unwrap();
    let parsed = Config::from_json_str(&json).unwrap();
    assert_eq!(parsed.to_json_string().unwrap(), json);
}

#[test]
fn test_config_toml_round_trip() {
    let config = sample_config();
    let toml_str = toml::to_string_pretty(&config).unwrap();
    let parsed: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(
        parsed.to_json_string().unwrap(),
        config.to_json_string().unwrap()
    );
}

#[test]
fn test_config_yaml_round_trip() {
    let config = sample_config();
    let yaml_str = serde_yaml::to_string(&config).unwrap();
    let parsed: Config = serde_yaml::from_str(&yaml_str).unwrap();
    assert_eq!(
        parsed.to_json_string().unwrap(),
        config.to_json_string().unwrap()
    );
}

#[test]
fn test_from_file_json_extension() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let config = sample_config();
    std::fs::write(&path, config.to_json_string().unwrap()).unwrap();

    let loaded = Config::from_file(path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.nodes.len(), 3);
    assert_eq!(loaded.nodes[0].encryption.as_deref(), Some("aes-256-gcm"));
    assert_eq!(loaded.nodes[1].transport, "ws");
    assert_eq!(loaded.nodes[2].anytls_min_idle_session, Some(4));
    assert_eq!(
        loaded.experimental.clash_api.external_controller,
        "0.0.0.0:9999"
    );
    assert_eq!(
        loaded.to_json_string().unwrap(),
        config.to_json_string().unwrap()
    );
}

#[test]
fn test_to_file_and_from_file_by_extension() {
    let dir = tempfile::tempdir().unwrap();
    let config = sample_config();

    for ext in ["json", "toml", "yaml", "yml"] {
        let path = dir.path().join(format!("config.{}", ext));
        config.to_file(path.to_str().unwrap()).unwrap();
        let loaded = Config::from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(
            loaded.to_json_string().unwrap(),
            config.to_json_string().unwrap(),
            "round trip failed for extension .{}",
            ext
        );
    }
}

#[test]
fn test_from_file_dae_fallback_chain() {
    // Extension-less and unknown-extension files keep the dae-first chain.
    let dir = tempfile::tempdir().unwrap();
    let dae = "global {\n    tproxy_port: 12346\n}\n";
    for name in ["config", "config.dae"] {
        let path = dir.path().join(name);
        std::fs::write(&path, dae).unwrap();
        let loaded = Config::from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.global.tproxy_port, 12346);
    }
}

#[test]
fn test_fragment_name_is_utf8_decoded() {
    // Regression: percent-encoded bytes must be decoded as UTF-8, not as
    // per-byte chars (which produced mojibake for Chinese/emoji names).
    let node = Node::from_share_link(
        "trojan://pw@hk.example.com:443/#%E9%A6%99%E6%B8%AF%20%E8%8A%82%E7%82%B9",
    )
    .unwrap();
    assert_eq!(node.name, "香港 节点");

    let node = Node::from_share_link(
        "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:443/#%F0%9F%87%AD%F0%9F%87%B0%20HK",
    )
    .unwrap();
    assert_eq!(node.name, "🇭🇰 HK");
    assert_eq!(node.encryption.as_deref(), Some("aes-256-gcm"));
    assert_eq!(node.password.as_deref(), Some("pw"));
}

#[test]
fn test_ss_full_base64_authority_with_fragment() {
    // SIP002 full-base64 form: ss://base64(method:password@host:port)#name
    let inner = b64("aes-128-gcm:secret-pw@sg.example.com:8388");
    let link = format!("ss://{}#%E6%96%B0%E5%8A%A0%E5%9D%A1", inner);
    let node = Node::from_share_link(&link).unwrap();
    assert_eq!(node.protocol, NodeProtocol::SS);
    assert_eq!(node.host, "sg.example.com");
    assert_eq!(node.port, 8388);
    assert_eq!(node.encryption.as_deref(), Some("aes-128-gcm"));
    assert_eq!(node.password.as_deref(), Some("secret-pw"));
    assert_eq!(node.name, "新加坡");
}

#[test]
fn test_name_fallback_never_contains_credentials() {
    // Links without #name get a `scheme-host` fallback; the raw URI (with
    // the password) must never end up in the display name.
    let node = Node::from_share_link("trojan://super-secret@us.example.com:443").unwrap();
    assert_eq!(node.name, "trojan-us.example.com");
    assert!(!node.name.contains("super-secret"));

    let node = Node::from_share_link("socks5://user:pass@10.0.0.1:1080").unwrap();
    assert_eq!(node.name, "socks5-10.0.0.1");
    assert!(!node.name.contains("pass"));
}

#[test]
fn test_percent_encoded_userinfo_is_decoded() {
    // Regression: encoded UUIDs in userinfo must be decoded, otherwise
    // AnyTLS/Trojan auth computes over the wrong string.
    let node = Node::from_share_link(
        "anytls://00000000%2D0000%2D0000%2D0000%2D000000000000@example.com:443/?sni=example.com#test-node",
    )
    .unwrap();
    assert_eq!(
        node.password.as_deref(),
        Some("00000000-0000-0000-0000-000000000000")
    );
    assert_eq!(node.sni.as_deref(), Some("example.com"));

    let node = Node::from_share_link("trojan://pass%40word%3Ax@h.example.com:443").unwrap();
    assert_eq!(node.password.as_deref(), Some("pass@word:x"));
}

#[test]
fn test_hysteria2_auth_and_obfs_params() {
    // The auth secret lives bare in the userinfo; it must reach both
    // `hy2_auth` and the `password` fallback the handler resolves.
    let node =
        Node::from_share_link("hysteria2://pass@example.com:443/?sni=example.com&insecure=1")
            .unwrap();
    assert_eq!(node.protocol, NodeProtocol::Hysteria2);
    assert_eq!(node.hy2_auth.as_deref(), Some("pass"));
    assert_eq!(node.password.as_deref(), Some("pass"));
    assert_eq!(node.sni.as_deref(), Some("example.com"));
    assert!(node.skip_cert_verify);
    assert!(node.hy2_obfs.is_none());

    // Percent-encoded secrets are decoded; salamander obfs password lands in
    // `hy2_obfs`; the fragment names the node.
    let node = Node::from_share_link(
        "hysteria2://p%40ss%3Aword@example.com:443/?obfs=salamander&obfs-password=obfspw#my-hy2",
    )
    .unwrap();
    assert_eq!(node.hy2_auth.as_deref(), Some("p@ss:word"));
    assert_eq!(node.hy2_obfs.as_deref(), Some("obfspw"));
    assert_eq!(node.name, "my-hy2");

    // obfs without a password leaves obfuscation off.
    let node = Node::from_share_link("hysteria2://pass@example.com:443/?obfs=salamander").unwrap();
    assert!(node.hy2_obfs.is_none());

    // Brutal bandwidth hints.
    let node =
        Node::from_share_link("hysteria2://pass@example.com:443/?upmbps=50&downmbps=200").unwrap();
    assert_eq!(node.hy2_up_mbps, Some(50));
    assert_eq!(node.hy2_down_mbps, Some(200));

    // Port hopping and certificate pin.
    let node = Node::from_share_link(
        "hysteria2://pass@example.com:443/?mport=20000-20010,30000&mhop=15&pinSHA256=aabbcc",
    )
    .unwrap();
    assert_eq!(node.hy2_port_hopping.as_deref(), Some("20000-20010,30000"));
    assert_eq!(node.hy2_hop_interval, Some(15));
    assert_eq!(node.tls_pin_sha256.as_deref(), Some("aabbcc"));
}

#[test]
fn test_ech_query_params() {
    // ech_config=<base64url ECHConfigList> enables ECH and carries the config.
    let node = Node::from_share_link(
        "hysteria2://pass@example.com:443/?sni=example.com&ech_config=QUJDMTIz",
    )
    .unwrap();
    assert!(node.ech_enabled);
    assert_eq!(node.ech_config.as_deref(), Some("QUJDMTIz"));

    // Bare ech=1 toggles ECH without keys.
    let node = Node::from_share_link("tuic://u:p@example.com:443/?ech=1").unwrap();
    assert!(node.ech_enabled);
    assert!(node.ech_config.is_none());
}

#[test]
fn test_tuic_window_params() {
    let node = Node::from_share_link(
        "tuic://u:p@example.com:443/?initStreamReceiveWindow=4194304&initConnReceiveWindow=16777216",
    )
    .unwrap();
    assert_eq!(node.tuic_init_stream_recv_window, Some(4194304));
    assert_eq!(node.tuic_init_conn_recv_window, Some(16777216));
    // Unset by default.
    let node = Node::from_share_link("tuic://u:p@example.com:443").unwrap();
    assert_eq!(node.tuic_init_stream_recv_window, None);

    // No ECH params: disabled.
    let node = Node::from_share_link("trojan://pass@example.com:443").unwrap();
    assert!(!node.ech_enabled);
    assert!(node.ech_config.is_none());
}

#[test]
fn test_tuic_alpn_and_congestion_params() {
    let node = Node::from_share_link(
        "tuic://d4d633d1-e9db-44dc-a458-fc6fe81beba4:d4d633d1-e9db-44dc-a458-fc6fe81beba4@[2a03:4000:37:a0f:48d0:aff:fe96:e75b]:37618/?congestion_control=bbr&alpn=h3&insecure=1",
    )
    .unwrap();
    assert_eq!(node.tuic_alpn.as_deref(), Some("h3"));
    assert_eq!(node.tuic_congestion.as_deref(), Some("bbr"));

    // Comma-separated ALPN list is preserved verbatim.
    let node = Node::from_share_link("tuic://u:p@example.com:443/?alpn=h3,h3-29").unwrap();
    assert_eq!(node.tuic_alpn.as_deref(), Some("h3,h3-29"));

    // Unset by default.
    let node = Node::from_share_link("tuic://u:p@example.com:443").unwrap();
    assert_eq!(node.tuic_alpn, None);
    assert_eq!(node.tuic_congestion, None);
}
