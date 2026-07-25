//! Share-link parsing: build a [`Node`] from a proxy share URI.
//!
//! Supports the common `scheme://` share-link formats (socks5, ss/ssr,
//! trojan/trojan-go, anytls, vmess, vless, hysteria2, tuic, juicity, http).
//! Shadowsocks links follow SIP002: the userinfo is either
//! `base64(method:password)` or plain `method:password` (the method itself
//! may still be base64-encoded), the whole `method:password@host:port`
//! authority may also be base64-encoded, and an optional `/?plugin=...`
//! query suffix carries the plugin name and options.
//!
//! Two schemes do not follow the URL-shaped layout and are decoded before
//! the generic URL path:
//!
//! - `vmess://<base64>` — the payload is base64 (URL-safe or standard
//!   alphabet) of a JSON object with the v2rayN field set (`add`, `port`,
//!   `id`, `scy`, `net`, `host`, `path`, `tls`, `sni`, ...).
//! - `ssr://<base64>` — the payload is base64 of
//!   `host:port:protocol:method:obfs:base64(password)/?params`, where the
//!   `obfsparam`/`protoparam`/`remarks`/`group` params are themselves
//!   URL-safe base64 without padding.
//!
//! This is the single share-link parser for the whole workspace: the dae
//! config parser, the core subscription fetcher, and the API server import
//! paths all delegate to [`Node::from_share_link`].

use std::collections::HashMap;

use base64::Engine as _;

use crate::error::ConfigError;
use crate::node::{Node, PortRange};
use crate::types::NodeProtocol;

impl Node {
    /// Parse a proxy share link (e.g. `ss://...`, `trojan://...`) into a [`Node`].
    ///
    /// A link may describe a chain (`a -> b`); only the first hop is parsed.
    pub fn from_share_link(link: &str) -> Result<Node, ConfigError> {
        let first = link.split("->").next().unwrap_or("").trim();

        // vmess:// and ssr:// carry a base64-encoded payload in place of a
        // URL-shaped authority, so they are decoded before the generic path.
        if let Some(payload) = first.strip_prefix("vmess://") {
            return parse_vmess_link(first, payload);
        }
        if let Some(payload) = first.strip_prefix("ssr://") {
            return parse_ssr_link(first, payload);
        }

        // SIP002 also allows the whole authority to be base64-encoded
        // (`ss://base64(method:password@host:port)#name`). Decode that form
        // up front: the URL parser would otherwise treat (and lowercase) the
        // payload as a host name.
        let decoded_ss;
        let first = match first.strip_prefix("ss://") {
            Some(rest) => match decode_full_base64_ss_link(rest) {
                Some(rebuilt) => {
                    decoded_ss = rebuilt;
                    decoded_ss.as_str()
                }
                None => first,
            },
            None => first,
        };

        // Hysteria2 extends the URI authority with a comma-separated port
        // union (for example `:443,8443,40000-50000`). `url::Url` correctly
        // rejects that non-standard port syntax, so normalize it to one
        // representative port for ordinary URL parsing while retaining the
        // full union on the Node for the QUIC port-hopper.
        let mut normalized_hy2 = None;
        let mut hy2_port_ranges = Vec::new();
        if let Some((normalized, ranges)) = normalize_hysteria2_port_hopping_uri(first)? {
            normalized_hy2 = Some(normalized);
            hy2_port_ranges = ranges;
        }
        let first = normalized_hy2.as_deref().unwrap_or(first);

        let url = url::Url::parse(first)
            .map_err(|e| ConfigError::Parse(format!("invalid share link '{}': {}", first, e)))?;
        let scheme = url.scheme();

        let protocol = match scheme {
            "socks5" | "socks4" | "socks4a" => NodeProtocol::Socks5,
            "ss" => NodeProtocol::SS,
            "ssr" => NodeProtocol::SSR,
            "trojan" | "trojan-go" => NodeProtocol::Trojan,
            "anytls" => NodeProtocol::AnyTLS,
            "vmess" => NodeProtocol::VMess,
            "vless" => NodeProtocol::VLess,
            "hysteria2" | "hysteria" | "hy2" => NodeProtocol::Hysteria2,
            "tuic" => NodeProtocol::Tuic,
            "juicity" => NodeProtocol::Juicity,
            "http" | "https" => NodeProtocol::HTTP,
            _ => return Err(ConfigError::UnknownProtocol(scheme.to_string())),
        };

        let host = url
            .host_str()
            .ok_or_else(|| ConfigError::Parse(format!("missing host in share link '{}'", first)))?
            .to_string();
        let port = url.port().unwrap_or(match protocol {
            NodeProtocol::HTTP => 80,
            _ => 443,
        });

        let mut node = Node {
            id: uuid::Uuid::new_v4(),
            protocol,
            host: host.clone(),
            address: format!("{}:{}", host, port),
            port,
            hy2_port_ranges,
            ..Default::default()
        };

        if protocol == NodeProtocol::SS {
            apply_ss_userinfo(&mut node, &url);
        } else {
            // The `url` crate returns userinfo still percent-encoded
            // (`d2d53752%2D0985...`). Decode it so auth secrets match what
            // the server expects — an encoded UUID otherwise hashes to a
            // completely different AnyTLS/Trojan credential.
            if !url.username().is_empty() {
                node.username = Some(percent_decode_str(url.username()));
            }
            if let Some(pw) = url.password() {
                node.password = Some(percent_decode_str(pw));
            }

            // Hysteria2 puts `auth` in the URI userinfo. Unlike Trojan-like
            // links, it may deliberately be a `username:password` pair, so
            // preserve both components as one protocol-level auth value.
            if protocol == NodeProtocol::Hysteria2 && !url.username().is_empty() {
                let username = percent_decode_str(url.username());
                node.hy2_auth = Some(match url.password() {
                    Some(password) => {
                        format!("{}:{}", username, percent_decode_str(password))
                    }
                    None => username,
                });
            }

            // Trojan, Trojan-Go and AnyTLS put the authentication secret in the
            // URI userinfo field, not the password field.  Copy it to
            // `password` so the protocol handler can build the correct request
            // header.
            if matches!(
                protocol,
                NodeProtocol::Trojan | NodeProtocol::TrojanGo | NodeProtocol::AnyTLS
            ) && node.password.is_none()
                && !url.username().is_empty()
            {
                node.password = Some(percent_decode_str(url.username()));
            }
        }

        // Use the URL fragment (#name) as the display name if present.
        // Otherwise fall back to `scheme-host` — never the raw URI, which
        // would leak the credentials into node lists and dashboards.
        node.name = url
            .fragment()
            .map(decode_url_fragment)
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("{}-{}", scheme, host));

        match protocol {
            NodeProtocol::Trojan
            | NodeProtocol::TrojanGo
            | NodeProtocol::VLess
            | NodeProtocol::AnyTLS => {
                node.tls = true;
            }
            NodeProtocol::HTTP => {
                node.tls = scheme == "https";
            }
            _ => {}
        }

        let query: HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        // Transport selection comes first so that transport-specific
        // parameters (ws path/host, grpc service name) can be interpreted.
        if let Some(v) = query.get("type").or_else(|| query.get("network")) {
            node.transport = v.clone();
        }
        if let Some(v) = query.get("sni") {
            node.sni = Some(v.clone());
        }

        // Trojan/Trojan-Go transport options.  `alpn` is accepted for
        // compatibility but intentionally not stored.
        let mut host_consumed = false;
        if matches!(protocol, NodeProtocol::Trojan | NodeProtocol::TrojanGo) {
            match node.transport.as_str() {
                "ws" => {
                    if let Some(v) = query.get("host") {
                        node.ws_host = Some(v.clone());
                        host_consumed = true;
                    }
                    if let Some(v) = query.get("path") {
                        node.ws_path = Some(v.clone());
                    }
                }
                "grpc" => {
                    if let Some(v) = query
                        .get("serviceName")
                        .or_else(|| query.get("service_name"))
                    {
                        node.grpc_service = Some(v.clone());
                    }
                }
                _ => {}
            }
        }

        // `host=` falls back to the TLS SNI unless it was already consumed as
        // a transport option above.
        if node.sni.is_none()
            && !host_consumed
            && let Some(v) = query.get("host")
        {
            node.sni = Some(v.clone());
        }

        if let Some(v) = query
            .get("allowInsecure")
            .or_else(|| query.get("allow_insecure"))
            .or_else(|| query.get("insecure"))
        {
            node.skip_cert_verify = v == "1" || v.eq_ignore_ascii_case("true");
        }

        // Certificate SHA-256 pin (`pinSHA256=<hex>`) — replaces PKI
        // verification with a leaf-certificate fingerprint check.
        if let Some(v) = query.get("pinSHA256").or_else(|| query.get("pin_sha256")) {
            node.tls_pin_sha256 = Some(v.clone());
        }

        // ECH (Encrypted Client Hello): `ech_config=<base64 ECHConfigList>`
        // enables real ECH; bare `ech=1` toggles it on without keys (GREASE
        // only until DNS HTTPS-RR lookup lands).
        if let Some(v) = query.get("ech_config").or_else(|| query.get("echconfig")) {
            node.ech_enabled = true;
            node.ech_config = Some(v.clone());
        } else if let Some(v) = query.get("ech") {
            node.ech_enabled = v == "1" || v.eq_ignore_ascii_case("true");
        }

        if let Some(v) = query.get("plugin") {
            // SIP002 packs the plugin as `name;opt=k;...` in a single
            // parameter; other protocols pass the plugin name verbatim.
            if protocol == NodeProtocol::SS {
                if let Some((name, opts)) = v.split_once(';') {
                    node.plugin = Some(name.to_string());
                    if !opts.is_empty() {
                        node.plugin_opts = Some(opts.to_string());
                    }
                } else {
                    node.plugin = Some(v.clone());
                }
            } else {
                node.plugin = Some(v.clone());
            }
        }
        if let Some(v) = query
            .get("plugin-opts")
            .or_else(|| query.get("plugin_opts"))
        {
            node.plugin_opts = Some(v.clone());
        }

        if protocol == NodeProtocol::Hysteria2 {
            // hy2 puts the auth secret bare in the userinfo
            // (`hysteria2://password@host`); the handler reads `hy2_auth`
            // first and falls back to `password`, so populate both.
            if node.hy2_auth.is_none() {
                node.hy2_auth = node.username.clone();
            }
            if node.password.is_none() {
                node.password = node.username.clone();
            }
            // Salamander obfuscation: `obfs=salamander&obfs-password=...`.
            if query.get("obfs").is_some_and(|v| v == "salamander")
                && let Some(v) = query.get("obfs-password").filter(|s| !s.is_empty())
            {
                node.hy2_obfs = Some(v.clone());
            }
            // Brutal bandwidth hints (`upmbps`/`downmbps`).
            if let Some(v) = query.get("upmbps") {
                node.hy2_up_mbps = v.parse().ok();
            }
            if let Some(v) = query.get("downmbps") {
                node.hy2_down_mbps = v.parse().ok();
            }
            // Port hopping (`mport=20000-30000` / `mport=p1,p2`, `mhop=secs`).
            if let Some(v) = query.get("mport").filter(|s| !s.is_empty()) {
                node.hy2_port_hopping = Some(v.clone());
            }
            if let Some(v) = query.get("mhop") {
                node.hy2_hop_interval = v.parse().ok();
            }
            // QUIC flow-control / MTU knobs (hy2 client config parity).
            if let Some(v) = query.get("initStreamReceiveWindow") {
                node.hy2_init_stream_recv_window = v.parse().ok();
            }
            if let Some(v) = query.get("initConnReceiveWindow") {
                node.hy2_init_conn_recv_window = v.parse().ok();
            }
            if let Some(v) = query.get("disablePathMTUDiscovery") {
                node.hy2_disable_mtu_discovery = Some(v == "1" || v.eq_ignore_ascii_case("true"));
            }
        }

        if protocol == NodeProtocol::AnyTLS {
            // The AnyTLS secret doubles as the session-pool password.
            node.anytls_password = node.password.clone();
            if let Some(v) = query.get("idle_session_check_interval") {
                node.anytls_idle_session_check_interval = parse_duration_secs(v);
            }
            if let Some(v) = query.get("idle_session_timeout") {
                node.anytls_idle_session_timeout = parse_duration_secs(v);
            }
            if let Some(v) = query.get("min_idle_session") {
                node.anytls_min_idle_session = v.parse::<u16>().ok().map(usize::from);
            }
        }

        if protocol == NodeProtocol::Hysteria2
            && query
                .get("obfs")
                .is_some_and(|kind| kind.eq_ignore_ascii_case("salamander"))
            && let Some(password) = query
                .get("obfs-password")
                .filter(|password| !password.is_empty())
        {
            node.hy2_obfs = Some(password.clone());
        }

        Ok(node)
    }
}

/// Normalize Hysteria2's non-standard multi-port URI authority before it is
/// handed to `url::Url`. The original port union is returned separately so
/// the caller can retain it for actual QUIC hopping.
fn normalize_hysteria2_port_hopping_uri(
    link: &str,
) -> Result<Option<(String, Vec<PortRange>)>, ConfigError> {
    let Some((scheme, after_scheme)) = link.split_once("://") else {
        return Ok(None);
    };
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "hysteria2" | "hysteria" | "hy2"
    ) {
        return Ok(None);
    }

    let authority_end = after_scheme
        .char_indices()
        .find_map(|(idx, ch)| matches!(ch, '/' | '?' | '#').then_some(idx))
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let suffix = &after_scheme[authority_end..];
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (format!("{userinfo}@"), host_port),
        None => (String::new(), authority),
    };
    let Some((host, port_spec)) = split_hysteria2_host_port(host_port)? else {
        // Keep the generic parser's normal `:443` fallback for an ordinary
        // Hysteria2 URI that omits a port altogether.
        return Ok(None);
    };

    if !port_spec.contains(',') && !port_spec.contains('-') {
        return Ok(None);
    }

    let ranges = parse_hysteria2_port_union(port_spec)?;
    let representative = ranges
        .first()
        .expect("validated Hysteria2 port union is non-empty")
        .start;
    Ok(Some((
        format!("{scheme}://{userinfo}{host}:{representative}{suffix}"),
        ranges,
    )))
}

/// Split a Hysteria2 URI authority into the host (including IPv6 brackets)
/// and an optional port expression.
///
/// A normal URI may omit its port and rely on the Hysteria2 default of 443;
/// only a port expression containing a union needs special normalization.
fn split_hysteria2_host_port(authority: &str) -> Result<Option<(&str, &str)>, ConfigError> {
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']').ok_or_else(|| {
            ConfigError::Parse("invalid Hysteria2 URI: unterminated IPv6 host".into())
        })?;
        let host = &authority[..=close];
        let suffix = &authority[close + 1..];
        if suffix.is_empty() {
            return Ok(None);
        }
        let port = suffix.strip_prefix(':').ok_or_else(|| {
            ConfigError::Parse("invalid Hysteria2 URI: invalid text after IPv6 host".into())
        })?;
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some(parts) => parts,
            None => return Ok(None),
        }
    };
    if host.is_empty() || port.is_empty() {
        return Err(ConfigError::Parse(
            "invalid Hysteria2 URI: empty host or port".into(),
        ));
    }
    Ok(Some((host, port)))
}

/// Parse Hysteria2's comma-separated union of individual ports and inclusive
/// port ranges. Port zero is invalid for an outbound UDP peer.
fn parse_hysteria2_port_union(port_spec: &str) -> Result<Vec<PortRange>, ConfigError> {
    fn parse_port(raw: &str, port_spec: &str) -> Result<u16, ConfigError> {
        let port = raw.trim().parse::<u16>().map_err(|_| {
            ConfigError::Parse(format!("invalid Hysteria2 port union '{port_spec}'"))
        })?;
        if port == 0 {
            return Err(ConfigError::Parse(format!(
                "invalid Hysteria2 port union '{port_spec}': port 0 is not allowed"
            )));
        }
        Ok(port)
    }

    let mut ranges = Vec::new();
    for raw_item in port_spec.split(',') {
        let item = raw_item.trim();
        if item.is_empty() {
            return Err(ConfigError::Parse(format!(
                "invalid Hysteria2 port union '{port_spec}'"
            )));
        }
        let range = match item.split_once('-') {
            Some((start, end)) if !end.contains('-') => {
                let start = parse_port(start, port_spec)?;
                let end = parse_port(end, port_spec)?;
                if start > end {
                    return Err(ConfigError::Parse(format!(
                        "invalid Hysteria2 port range '{item}': start exceeds end"
                    )));
                }
                PortRange { start, end }
            }
            Some(_) => {
                return Err(ConfigError::Parse(format!(
                    "invalid Hysteria2 port range '{item}'"
                )));
            }
            None => {
                let port = parse_port(item, port_spec)?;
                PortRange {
                    start: port,
                    end: port,
                }
            }
        };
        ranges.push(range);
    }
    Ok(ranges)
}

/// Parse a `vmess://` share link: base64 of a JSON object (v2rayN schema).
fn parse_vmess_link(link: &str, payload: &str) -> Result<Node, ConfigError> {
    let raw = base64_decode_flexible(payload).ok_or_else(|| {
        ConfigError::Parse(format!(
            "invalid vmess link '{}': base64 decode failed",
            link
        ))
    })?;
    let text = String::from_utf8(raw).map_err(|_| {
        ConfigError::Parse(format!(
            "invalid vmess link '{}': payload is not UTF-8",
            link
        ))
    })?;
    let json: VmessLinkJson = serde_json::from_str(&text)
        .map_err(|e| ConfigError::Parse(format!("invalid vmess link '{}': {}", link, e)))?;
    json.into_node(link)
}

/// Field set of a base64-JSON `vmess://` share link (v2rayN schema).
///
/// `port`/`aid` are modelled as [`serde_json::Value`] because exporters
/// disagree on quoting them.
#[derive(serde::Deserialize)]
struct VmessLinkJson {
    /// Remark / display name.
    ps: Option<String>,
    /// Server host.
    add: Option<String>,
    /// Server port (string or number).
    port: Option<serde_json::Value>,
    /// User UUID.
    id: Option<String>,
    /// AlterId — accepted for compatibility; AEAD (alterId=0) is assumed.
    #[allow(dead_code)]
    aid: Option<serde_json::Value>,
    /// Cipher (`scy` in newer links, `security` in older ones).
    scy: Option<String>,
    security: Option<String>,
    /// Transport: tcp / ws / grpc / h2 / kcp.
    net: Option<String>,
    /// Transport header type; accepted for compatibility, not stored.
    #[allow(dead_code)]
    r#type: Option<String>,
    /// WS host header on `net = "ws"` links, TLS SNI elsewhere.
    host: Option<String>,
    /// WS path, or gRPC service name on `net = "grpc"` links.
    path: Option<String>,
    /// TLS flag: the exact string "tls" enables it.
    tls: Option<String>,
    /// Explicit TLS SNI (takes precedence over `host`).
    sni: Option<String>,
    /// ALPN; accepted for compatibility, not stored.
    #[allow(dead_code)]
    alpn: Option<String>,
}

impl VmessLinkJson {
    fn into_node(self, link: &str) -> Result<Node, ConfigError> {
        let host = self.add.filter(|h| !h.is_empty()).ok_or_else(|| {
            ConfigError::Parse(format!(
                "invalid vmess link '{}': missing server address",
                link
            ))
        })?;
        let port = json_port(self.port).ok_or_else(|| {
            ConfigError::Parse(format!(
                "invalid vmess link '{}': missing or bad port",
                link
            ))
        })?;
        let id = self.id.filter(|s| !s.is_empty()).ok_or_else(|| {
            ConfigError::Parse(format!("invalid vmess link '{}': missing user id", link))
        })?;

        let transport = self.net.unwrap_or_default();

        let mut node = Node {
            id: uuid::Uuid::new_v4(),
            protocol: NodeProtocol::VMess,
            host: host.clone(),
            address: format!("{}:{}", host, port),
            port,
            password: Some(id),
            encryption: self.scy.or(self.security),
            transport: transport.clone(),
            tls: self.tls.as_deref() == Some("tls"),
            name: self.ps.unwrap_or_else(|| format!("vmess-{}", host)),
            ..Default::default()
        };
        if !transport.is_empty() {
            node.network = Some(transport.clone());
        }

        // `host` is the WS host header on ws links and the TLS SNI elsewhere;
        // an explicit `sni` field wins over both.
        if let Some(v) = self.host.filter(|s| !s.is_empty()) {
            if transport == "ws" {
                node.ws_host = Some(v);
            } else {
                node.sni = Some(v);
            }
        }
        if let Some(v) = self.sni.filter(|s| !s.is_empty()) {
            node.sni = Some(v);
        }
        if let Some(v) = self.path.filter(|s| !s.is_empty()) {
            match transport.as_str() {
                "ws" => node.ws_path = Some(v),
                "grpc" => node.grpc_service = Some(v),
                _ => {}
            }
        }

        Ok(node)
    }
}

/// Extract a port from a JSON value that may be a string or a number.
fn json_port(value: Option<serde_json::Value>) -> Option<u16> {
    match value? {
        serde_json::Value::Number(n) => n.as_u64().and_then(|v| u16::try_from(v).ok()),
        serde_json::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Parse an `ssr://` share link.
///
/// The payload is base64 of
/// `host:port:protocol:method:obfs:base64(password)/?key=base64(value)&...`;
/// the `/?params` section is optional.
fn parse_ssr_link(link: &str, payload: &str) -> Result<Node, ConfigError> {
    let raw = base64_decode_flexible(payload).ok_or_else(|| {
        ConfigError::Parse(format!("invalid ssr link '{}': base64 decode failed", link))
    })?;
    let text = String::from_utf8(raw).map_err(|_| {
        ConfigError::Parse(format!("invalid ssr link '{}': payload is not UTF-8", link))
    })?;

    let (main, query) = match text.split_once("/?") {
        Some((m, q)) => (m, Some(q)),
        None => (text.trim_end_matches('/'), None),
    };

    // Peel the five right-most fields; the remainder is the host (which may
    // itself contain ':' for bracketed IPv6 literals).
    let mut fields = main.rsplitn(6, ':');
    let password_b64 = fields.next().unwrap_or("");
    let obfs = fields.next().unwrap_or("");
    let method = fields.next().unwrap_or("");
    let ssr_protocol = fields.next().unwrap_or("");
    let port_str = fields.next().unwrap_or("");
    let host = fields.next().unwrap_or("");

    if host.is_empty() || obfs.is_empty() || method.is_empty() || ssr_protocol.is_empty() {
        return Err(ConfigError::Parse(format!(
            "invalid ssr link '{}': expected host:port:protocol:method:obfs:password",
            link
        )));
    }
    let port: u16 = port_str.parse().map_err(|_| {
        ConfigError::Parse(format!(
            "invalid ssr link '{}': bad port '{}'",
            link, port_str
        ))
    })?;
    let password = base64_decode_flexible(password_b64)
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| {
            ConfigError::Parse(format!("invalid ssr link '{}': bad password field", link))
        })?;

    // Query parameters are URL-safe base64 without padding.
    let mut remarks = None;
    let mut obfs_param = None;
    let mut proto_param = None;
    if let Some(query) = query {
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            let decoded = base64_decode_flexible(value).and_then(|b| String::from_utf8(b).ok());
            match key {
                "remarks" => remarks = decoded,
                "obfsparam" => obfs_param = decoded,
                "protoparam" => proto_param = decoded,
                _ => {} // `group` and friends are accepted but not stored
            }
        }
    }

    let mut node = Node {
        id: uuid::Uuid::new_v4(),
        protocol: NodeProtocol::SSR,
        host: host.to_string(),
        address: format!("{}:{}", host, port),
        port,
        encryption: Some(method.to_string()),
        password: Some(password),
        // The SSR handler detects both the protocol and the obfs plugin by
        // substring-matching `node.plugin`; carry both names there.
        plugin: Some(format!("{};{}", ssr_protocol, obfs)),
        name: remarks.unwrap_or_else(|| format!("ssr-{}", host)),
        ..Default::default()
    };

    // Surface the decoded plugin parameters as `k=v;...` pairs, the format
    // `SsrObfs::parse_opts` understands.
    let mut opts = Vec::new();
    if let Some(v) = obfs_param.filter(|s| !s.is_empty()) {
        opts.push(format!("obfsparam={}", v));
    }
    if let Some(v) = proto_param.filter(|s| !s.is_empty()) {
        opts.push(format!("protoparam={}", v));
    }
    if !opts.is_empty() {
        node.plugin_opts = Some(opts.join(";"));
    }

    Ok(node)
}

/// Apply SIP002 userinfo decoding for Shadowsocks links.
///
/// The userinfo is `base64(method:password)` or plain `method:password`; the
/// decoded method lands in `encryption` and the password in `password`.
/// Note: the `url` crate percent-encodes `=` in userinfo, so the raw parts
/// are percent-decoded before any base64 decoding happens.
fn apply_ss_userinfo(node: &mut Node, url: &url::Url) {
    let userinfo = match url.password() {
        Some(pw) => format!(
            "{}:{}",
            percent_decode_str(url.username()),
            percent_decode_str(pw)
        ),
        None => percent_decode_str(url.username()),
    };
    if userinfo.is_empty() {
        return;
    }

    match decode_ss_userinfo(&userinfo) {
        Some((method, password)) => {
            node.encryption = Some(method);
            node.password = Some(password);
        }
        None => {
            // Unrecognized userinfo: keep it as the password so nothing is lost.
            node.password = Some(userinfo);
        }
    }
}

/// Decode a SIP002 userinfo string into `(method, password)`.
fn decode_ss_userinfo(userinfo: &str) -> Option<(String, String)> {
    if let Some((method, password)) = userinfo.split_once(':') {
        return Some((decode_ss_method(method), password.to_string()));
    }
    // Whole userinfo is base64(method:password).
    let decoded = base64_decode_flexible(userinfo)?;
    let text = String::from_utf8(decoded).ok()?;
    let (method, password) = text.split_once(':')?;
    Some((decode_ss_method(method), password.to_string()))
}

/// Decode a possibly base64-encoded cipher name.
///
/// Plain cipher names are returned unchanged; values that are not plausible
/// cipher names are base64-decoded when the result looks like one.
fn decode_ss_method(method: &str) -> String {
    if looks_like_cipher(method) {
        return method.to_string();
    }
    if let Some(decoded) = base64_decode_flexible(method)
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|s| looks_like_cipher(s))
    {
        return decoded;
    }
    method.to_string()
}

/// Heuristic: does this string look like a Shadowsocks cipher name?
fn looks_like_cipher(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && (s.contains('-') || matches!(s, "salsa20" | "chacha20" | "rc4"))
}

/// Decode the SIP002 full-base64 form `ss://base64(method:password@host:port)`,
/// keeping any `?query` / `#fragment` suffix, and return the rebuilt link.
/// Returns `None` for the (more common) forms that already carry an `@`.
fn decode_full_base64_ss_link(rest: &str) -> Option<String> {
    let end = rest.find(['?', '#', '/']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let text = String::from_utf8(base64_decode_flexible(authority)?).ok()?;
    if !text.contains('@') {
        return None;
    }
    Some(format!("ss://{}{}", text, &rest[end..]))
}

/// Base64-decode tolerantly: URL-safe without padding first, then the other
/// common alphabets/padding combinations.
fn base64_decode_flexible(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input))
        .ok()
}

/// Parse a duration string like `30s`, `1m` or `500ms` into seconds.
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(v) = s.strip_suffix("ms") {
        return v.parse::<f64>().ok().map(|v| (v / 1000.0).ceil() as u64);
    }
    if let Some(v) = s.strip_suffix('s') {
        return v.parse().ok();
    }
    if let Some(v) = s.strip_suffix('m') {
        return v.parse::<u64>().ok().map(|v| v * 60);
    }
    if let Some(v) = s.strip_suffix('h') {
        return v.parse::<u64>().ok().map(|v| v * 3600);
    }
    s.parse().ok()
}

/// Percent-decode a string into bytes, then lossily into UTF-8.
fn percent_decode_str(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(decoded) = hex_to_byte(bytes[i + 1], bytes[i + 2])
        {
            out.push(decoded);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decode a percent-encoded URL fragment into a plain UTF-8 string.
///
/// Percent-encoded bytes are decoded to raw bytes first and then interpreted
/// as UTF-8 — decoding each byte as a `char` directly would corrupt any
/// multi-byte (Chinese / emoji) node name.
fn decode_url_fragment(fragment: &str) -> String {
    percent_decode_str(fragment)
}

fn hex_to_byte(h: u8, l: u8) -> Result<u8, ()> {
    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let hi = hex_val(h).ok_or(())?;
    let lo = hex_val(l).ok_or(())?;
    Ok(hi << 4 | lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hysteria2_port_range_and_obfuscation() {
        let node = Node::from_share_link(
            "hysteria2://secret@[2001:db8::1]:40000-40002/?sni=example.com&obfs=salamander&obfs-password=obfs",
        )
        .expect("valid Hysteria2 port-hopping URI");

        assert_eq!(node.protocol, NodeProtocol::Hysteria2);
        assert_eq!(node.host, "[2001:db8::1]");
        assert_eq!(node.port, 40000);
        assert_eq!(node.hy2_auth.as_deref(), Some("secret"));
        assert_eq!(node.hy2_obfs.as_deref(), Some("obfs"));
        assert_eq!(node.sni.as_deref(), Some("example.com"));
        assert_eq!(
            node.hy2_port_ranges,
            vec![PortRange {
                start: 40000,
                end: 40002,
            }]
        );
        assert_eq!(node.hy2_port_hopping_ports(), vec![40000, 40001, 40002]);
    }

    #[test]
    fn parses_hy2_port_union_and_auth_pair() {
        let node =
            Node::from_share_link("hy2://user:pass@example.com:443,8443,10000-10002/?insecure=1")
                .expect("valid HY2 port union URI");

        assert_eq!(node.protocol, NodeProtocol::Hysteria2);
        assert_eq!(node.port, 443);
        assert_eq!(node.hy2_auth.as_deref(), Some("user:pass"));
        assert!(node.skip_cert_verify);
        assert_eq!(
            node.hy2_port_hopping_ports(),
            vec![443, 8443, 10000, 10001, 10002]
        );
    }

    #[test]
    fn hysteria2_single_or_missing_port_remains_a_normal_uri() {
        let single = Node::from_share_link("hysteria2://secret@example.com:443/?sni=example.com")
            .expect("single-port URI remains supported");
        assert!(single.hy2_port_ranges.is_empty());
        assert_eq!(single.port, 443);

        let implicit = Node::from_share_link("hysteria2://secret@example.com/?sni=example.com")
            .expect("implicit default port remains supported");
        assert!(implicit.hy2_port_ranges.is_empty());
        assert_eq!(implicit.port, 443);
    }

    #[test]
    fn rejects_invalid_hysteria2_port_union() {
        for link in [
            "hysteria2://secret@example.com:40002-40000/",
            "hysteria2://secret@example.com:0,443/",
            "hysteria2://secret@example.com:443,,8443/",
            "hysteria2://secret@example.com:443-444-445/",
        ] {
            assert!(Node::from_share_link(link).is_err(), "{link}");
        }
    }

    #[test]
    fn serializes_hysteria2_port_ranges_in_toml_node_tables() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct NodeList {
            nodes: Vec<Node>,
        }

        let source = Node::from_share_link("hy2://secret@example.com:443,8443,10000-10001/")
            .expect("valid Hysteria2 port union");
        let text = toml::to_string(&NodeList {
            nodes: vec![source.clone()],
        })
        .expect("serialize node table");
        assert!(text.contains("hy2_port_ranges"));
        let restored: NodeList = toml::from_str(&text).expect("deserialize node table");
        assert_eq!(
            restored.nodes[0].hy2_port_hopping_ports(),
            source.hy2_port_hopping_ports()
        );
    }
}
