//! Apply share-link query fields before validating and deriving node identity.

use crate::error::ConfigError;
use crate::node::{Hysteria2Config, Node, OutboundConfig, QuicOptions, VlessConfig};
use crate::options::vocab::{
    optional_flow, optional_text, stream_transport, verification_text, vmess_cipher,
};
use crate::types::{NodeProtocol, parse_duration_secs};

#[derive(Default)]
pub(super) struct Query(Vec<(String, String)>);

impl Query {
    fn push(&mut self, key: String, value: String) {
        self.0.push((key, value));
    }

    pub(super) fn get(&self, key: &str) -> Option<&String> {
        self.0
            .iter()
            .rev()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
    }

    fn values<'a>(&'a self, key: &str) -> impl Iterator<Item = &'a str> {
        self.0
            .iter()
            .filter(move |(candidate, _)| candidate == key)
            .map(|(_, value)| value.as_str())
    }

    fn verification_values_with_indices(&self) -> impl Iterator<Item = (usize, &str)> {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, (key, _))| {
                matches!(
                    key.as_str(),
                    "allowInsecure" | "allow_insecure" | "insecure"
                )
            })
            .map(|(index, (_, value))| (index, value.as_str()))
    }

    fn contains_key(&self, key: &str) -> bool {
        self.0.iter().any(|(candidate, _)| candidate == key)
    }
}

pub(super) fn parse_query(
    url: &url::Url,
    protocol: NodeProtocol,
    shadowrocket: bool,
) -> Result<Query, ConfigError> {
    let shadowrocket_vmess = shadowrocket && protocol == NodeProtocol::VMess;
    let mut query = Query::default();
    let mut mode_seen = false;
    for (key, value) in url.query_pairs() {
        let key = key.into_owned();
        if shadowrocket_vmess
            && !matches!(
                key.as_str(),
                "sni"
                    | "peer"
                    | "allowInsecure"
                    | "allow_insecure"
                    | "insecure"
                    | "type"
                    | "network"
                    | "obfs"
                    | "scy"
                    | "encryption"
            )
            && query.get(&key).is_some_and(|previous| {
                previous != &value
                    && !(key == "security"
                        && vmess_cipher([previous.as_str(), value.as_ref()]).is_ok())
            })
        {
            return Err(ConfigError::Parse(
                "duplicate VMess share-link parameter".into(),
            ));
        }
        if protocol == NodeProtocol::VLess
            && matches!(key.as_str(), "vless_mode" | "packetEncoding")
        {
            if mode_seen {
                return Err(ConfigError::Parse(
                    "duplicate VLESS share-link mode representation".into(),
                ));
            }
            mode_seen = true;
        }
        query.push(key, value.into_owned());
    }
    if protocol != NodeProtocol::VLess
        && (query.contains_key("vless_mode")
            || query.get("packetEncoding").is_some_and(|v| v != "none"))
    {
        return Err(ConfigError::Parse(
            "vless_mode/packetEncoding are valid only for VLESS share links".into(),
        ));
    }
    if shadowrocket_vmess {
        vmess_cipher(
            query
                .values("security")
                .filter(|value| !matches!(*value, "none" | "tls")),
        )
        .map_err(|reason| ConfigError::Parse(reason.into()))?;
        if ["pbk", "sid", "spx"]
            .iter()
            .any(|key| query.get(key).is_some_and(|value| !value.is_empty()))
        {
            return Err(ConfigError::Parse(
                "REALITY parameters are unsupported in encoded VMess links".into(),
            ));
        }
        if query.get("alterId").is_some_and(|value| value != "0") {
            return Err(ConfigError::Parse(
                "unsupported VMess share-link option".into(),
            ));
        }
    }
    Ok(query)
}

pub(super) fn apply_tls(
    node: &mut Node,
    query: &Query,
    shadowrocket: bool,
    source: &crate::diagnostic::SourceRef,
    emit: &mut impl FnMut(crate::diagnostic::DetailedDiagnostic),
) -> Result<(), ConfigError> {
    let protocol = node.protocol();
    let shadowrocket_vless = shadowrocket && protocol == NodeProtocol::VLess;
    let shadowrocket_vmess = shadowrocket && protocol == NodeProtocol::VMess;
    let security = query.get("security").map(String::as_str);
    let mut vless_tls = None;
    let mut reality = security == Some("reality");
    if protocol == NodeProtocol::VLess {
        vless_tls = match query.get("tls").map(String::as_str) {
            None => None,
            Some("0") => Some(false),
            Some("1") => Some(true),
            Some(_) => return Err(ConfigError::Parse("unsupported VLESS tls value".into())),
        };
        let reality_fields = ["pbk", "sid", "spx"]
            .iter()
            .any(|key| query.contains_key(key));
        if reality_fields && security.is_some_and(|value| value != "reality")
            || vless_tls.is_some_and(|enabled| {
                security.is_some_and(|value| (value != "none") != enabled)
                    || (!enabled && reality_fields)
            })
        {
            return Err(ConfigError::Parse(
                "conflicting VLESS TLS parameters".into(),
            ));
        }
        reality |= reality_fields;
    }

    if let Some(tls) = node.tls_mut() {
        tls.enabled = match protocol {
            NodeProtocol::Trojan | NodeProtocol::AnyTLS => true,
            NodeProtocol::VLess => match security {
                Some("none") => false,
                Some(_) => true,
                None => reality || vless_tls.unwrap_or(!shadowrocket_vless),
            },
            NodeProtocol::VMess if shadowrocket_vmess => {
                let security_tls = match security {
                    Some("none") => Some(false),
                    Some("tls") => Some(true),
                    _ => None,
                };
                match query.get("tls").map(String::as_str) {
                    None => security_tls.unwrap_or(false),
                    Some("0") => {
                        if security_tls == Some(true) {
                            return Err(ConfigError::Parse(
                                "conflicting VMess TLS parameters".into(),
                            ));
                        }
                        false
                    }
                    Some("1") => {
                        if security_tls == Some(false) {
                            return Err(ConfigError::Parse(
                                "conflicting VMess TLS parameters".into(),
                            ));
                        }
                        true
                    }
                    Some(_) => {
                        return Err(ConfigError::Parse("unsupported VMess tls value".into()));
                    }
                }
            }
            NodeProtocol::VMess => security.is_some_and(|value| value != "none"),
            _ => tls.enabled,
        };
        tls.sni = optional_text(
            query
                .values("sni")
                .map(Some)
                .chain(query.values("peer").map(Some)),
        )
        .map_err(|_| ConfigError::Parse("conflicting TLS server name parameters".into()))?
        .map(str::to_string);
        let mut verification = None;
        for (ordinal, value) in query.verification_values_with_indices() {
            let parsed = verification_text(value).map_err(|_| {
                ConfigError::Parse("invalid certificate verification boolean".into())
            })?;
            if let Some(previous) = verification {
                if previous != parsed {
                    return Err(ConfigError::Parse(
                        "conflicting certificate verification aliases".into(),
                    ));
                }
            } else {
                verification = Some(parsed);
            }
            if value.trim().eq_ignore_ascii_case("yes") || value.trim().eq_ignore_ascii_case("on") {
                let mut warning = crate::diagnostic::DetailedDiagnostic::warning(
                    "legacy-config-warning",
                    source.clone(),
                    crate::diagnostic::SettingPath::new("nodes").field("skip_cert_verify"),
                    crate::diagnostic::SafeValue::Redacted,
                    "yes/on now disables certificate verification; use true or false explicitly",
                );
                warning.entry_index = Some(ordinal + 1);
                emit(warning);
            }
        }
        if let Some(value) = verification {
            tls.skip_cert_verify = value;
        }
        tls.pin_sha256 = query
            .get("pinSHA256")
            .or_else(|| query.get("pin_sha256"))
            .cloned();
        if let Some(value) = query.get("ech_config").or_else(|| query.get("echconfig")) {
            tls.ech_enabled = true;
            tls.ech_config = Some(value.clone());
        } else if let Some(value) = query.get("ech") {
            tls.ech_enabled = value == "1" || value.eq_ignore_ascii_case("true");
        }
        if protocol == NodeProtocol::VLess && reality {
            tls.enabled = true;
            tls.reality_public_key = query.get("pbk").cloned();
            tls.reality_short_id = query.get("sid").cloned();
            tls.reality_spider_x = Some(
                query
                    .get("spx")
                    .filter(|value| !value.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "/".to_string()),
            );
        }
    }
    Ok(())
}
fn resolve_stream_transport(
    query: &Query,
    protocol: NodeProtocol,
) -> Result<Option<&str>, ConfigError> {
    let mut resolved = None;
    for (key, value) in &query.0 {
        let canonical = match key.as_str() {
            "type" | "network" => stream_transport(value)
                .map_err(|_| ConfigError::Parse("unsupported stream transport".into()))?,
            "obfs" if matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess) => {
                match value.as_str() {
                    "" | "none" => "tcp",
                    "websocket" => "ws",
                    "grpc" => "grpc",
                    _ => {
                        return Err(ConfigError::Parse(
                            if protocol == NodeProtocol::VLess {
                                "unsupported VLESS obfs transport"
                            } else {
                                "unsupported VMess obfs transport"
                            }
                            .into(),
                        ));
                    }
                }
            }
            _ => continue,
        };
        if resolved.is_some_and(|previous| previous != canonical) {
            return Err(ConfigError::Parse(
                "conflicting stream transport aliases".into(),
            ));
        }
        resolved = Some(canonical);
    }
    Ok(query
        .get("type")
        .or_else(|| query.get("network"))
        .map(String::as_str)
        .or(resolved))
}

pub(super) fn apply_transport(node: &mut Node, query: &Query) -> Result<(), ConfigError> {
    let protocol = node.protocol();
    let host_fallback = query.get("host").map(String::as_str);
    let host_sni_fallback = optional_text([host_fallback])
        .map_err(|_| ConfigError::Parse("invalid share-link host parameter".into()))?;
    let obfs_host = if matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess) {
        query.get("obfsParam").map(String::as_str)
    } else {
        None
    };
    let mut host_consumed = false;
    if let Some(transport) = node.transport_mut() {
        if let Some(value) = resolve_stream_transport(query, protocol)? {
            transport.transport = value.to_string();
        }
        let transport_kind = stream_transport(&transport.transport)
            .map_err(|_| ConfigError::Parse("unsupported stream transport".into()))?;
        match transport_kind {
            "ws" => {
                if let Some(value) = host_fallback.or(obfs_host) {
                    transport.ws_host = Some(value.to_string());
                    host_consumed = true;
                }
                transport.ws_path = query.get("path").cloned();
            }
            "grpc" => {
                transport.grpc_service = query
                    .get("serviceName")
                    .or_else(|| query.get("service_name"))
                    .or_else(|| {
                        (matches!(protocol, NodeProtocol::VLess | NodeProtocol::VMess)
                            && query.values("obfs").any(|value| value == "grpc"))
                        .then(|| query.get("path"))
                        .flatten()
                    })
                    .cloned();
            }
            _ => {}
        }
    }
    if !host_consumed
        && node.tls().is_some_and(|tls| tls.sni.is_none())
        && let Some(value) = host_sni_fallback
        && let Some(tls) = node.tls_mut()
    {
        tls.sni = Some(value.to_string());
    }
    Ok(())
}

pub(super) fn apply_protocol(
    node: &mut Node,
    query: &Query,
    embedded_hop_ports: Option<String>,
    shadowrocket: bool,
    source: &crate::diagnostic::SourceRef,
    emit: &mut impl FnMut(crate::diagnostic::DetailedDiagnostic),
) -> Result<(), ConfigError> {
    if node.protocol() != NodeProtocol::SS
        && ["plugin", "plugin-opts", "plugin_opts"]
            .iter()
            .any(|key| query.contains_key(key))
    {
        return Err(ConfigError::Parse(
            "plugin parameters are valid only for Shadowsocks links".into(),
        ));
    }
    match &mut node.outbound {
        OutboundConfig::Shadowsocks(config) => {
            if let Some(value) = query.get("plugin") {
                if let Some((name, options)) = value.split_once(';') {
                    config.plugin = Some(name.to_string());
                    if !options.is_empty() {
                        config.plugin_opts = Some(options.to_string());
                    }
                } else {
                    config.plugin = Some(value.clone());
                }
            }
            if let Some(value) = query
                .get("plugin-opts")
                .or_else(|| query.get("plugin_opts"))
            {
                config.plugin_opts = Some(value.clone());
            }
        }
        OutboundConfig::Vmess(config) if shadowrocket => {
            config.encryption = vmess_cipher(
                query.values("encryption").chain(query.values("scy")).chain(
                    query
                        .values("security")
                        .filter(|value| !matches!(*value, "none" | "tls")),
                ),
            )
            .map_err(|reason| ConfigError::Parse(reason.into()))?
            .map(str::to_owned)
            .or_else(|| config.encryption.take());
        }
        OutboundConfig::Vless(config) => apply_vless(config, query)?,
        OutboundConfig::Hysteria2(config) => {
            apply_hysteria2(config, query, embedded_hop_ports)?;
            for (ordinal, (key, value)) in query.0.iter().enumerate() {
                if key == "mhop" && value.parse::<u64>().is_err() {
                    let mut warning = crate::diagnostic::DetailedDiagnostic::warning(
                        "legacy-config-warning",
                        source.clone(),
                        crate::diagnostic::SettingPath::new("nodes").field("hy2_hop_interval"),
                        crate::diagnostic::SafeValue::Redacted,
                        "ignored mhop value; share links require unsigned integer seconds",
                    );
                    warning.entry_index = Some(ordinal + 1);
                    emit(warning);
                }
            }
            apply_mtu(&mut config.quic, query);
        }
        OutboundConfig::Tuic(config) => {
            for value in query
                .values("udp-relay-mode")
                .chain(query.values("udp_relay_mode"))
            {
                if !matches!(value, "" | "native") {
                    return Err(ConfigError::Parse("unsupported TUIC UDP relay mode".into()));
                }
            }
            config.init_stream_recv_window = query
                .get("initStreamReceiveWindow")
                .and_then(|value| value.parse().ok());
            config.init_conn_recv_window = query
                .get("initConnReceiveWindow")
                .and_then(|value| value.parse().ok());
            config.congestion = query
                .get("congestion_control")
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            config.alpn = query
                .get("alpn")
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            apply_mtu(&mut config.quic, query);
        }
        OutboundConfig::Juicity(config) => apply_mtu(&mut config.quic, query),
        OutboundConfig::AnyTls(config) => {
            config.idle_session_check_interval = query
                .get("idle_session_check_interval")
                .and_then(|value| parse_duration_secs(value));
            config.idle_session_timeout = query
                .get("idle_session_timeout")
                .and_then(|value| parse_duration_secs(value));
            config.min_idle_session = query
                .get("min_idle_session")
                .and_then(|value| value.parse::<u16>().ok())
                .map(usize::from);
        }
        _ => {}
    }
    Ok(())
}

fn apply_hysteria2(
    config: &mut Hysteria2Config,
    query: &Query,
    embedded_hop_ports: Option<String>,
) -> Result<(), ConfigError> {
    let mut obfs = false;
    for value in query.values("obfs") {
        match value {
            "" => {}
            "salamander" => obfs = true,
            _ => {
                return Err(ConfigError::Parse(
                    "unsupported Hysteria2 obfuscation".into(),
                ));
            }
        }
    }
    let mut password = None;
    for value in query
        .values("obfs-password")
        .chain(query.values("obfs_password"))
    {
        if password.is_some_and(|previous| previous != value) {
            return Err(ConfigError::Parse(
                "conflicting Hysteria2 obfuscation passwords".into(),
            ));
        }
        password = Some(value);
    }
    if obfs {
        config.obfs = password
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
    }
    config.up_mbps = query.get("upmbps").and_then(|value| value.parse().ok());
    config.down_mbps = query.get("downmbps").and_then(|value| value.parse().ok());
    let mport = query.get("mport").filter(|value| !value.is_empty());
    if mport.is_some() && embedded_hop_ports.is_some() {
        return Err(ConfigError::Parse(
            "hysteria2 port hopping specified in both address and mport".into(),
        ));
    }
    config.port_hopping = mport.cloned().or(embedded_hop_ports);
    config.hop_interval = query.get("mhop").and_then(|value| value.parse().ok());
    config.init_stream_recv_window = query
        .get("initStreamReceiveWindow")
        .and_then(|value| value.parse().ok());
    config.init_conn_recv_window = query
        .get("initConnReceiveWindow")
        .and_then(|value| value.parse().ok());
    config.disable_mtu_discovery = query
        .get("disablePathMTUDiscovery")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    Ok(())
}

fn apply_mtu(quic: &mut QuicOptions, query: &Query) {
    if let Some(mtu) = query
        .get("mtu")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|mtu| (1200..=65527).contains(mtu))
    {
        quic.mtu = Some(mtu);
    }
}

fn apply_vless(config: &mut VlessConfig, query: &Query) -> Result<(), ConfigError> {
    if let Some(parameter) = [
        "mux",
        "smux",
        "multiplex",
        "udp-over-tcp",
        "udp_over_tcp",
        "packet-encoding",
        "packet_encoding",
        "packet-addr",
        "packet_addr",
        "xudp",
        "only-tcp",
        "only_tcp",
        "brutal",
        "brutal-opts",
        "brutal_opts",
        "max-connections",
        "max_connections",
        "min-streams",
        "min_streams",
        "max-streams",
        "max_streams",
    ]
    .into_iter()
    .find(|parameter| query.contains_key(parameter))
    {
        return Err(ConfigError::Parse(format!(
            "unsupported VLESS share-link parameter '{parameter}'; use vless_mode"
        )));
    }
    if let Some(mode) = query.get("vless_mode") {
        config.mode = mode.parse()?;
    } else if let Some(encoding) = query.get("packetEncoding") {
        match encoding.as_str() {
            "xudp" => config.mode = crate::node::WireMode::Xudp,
            "none" => {}
            _ => {
                return Err(ConfigError::Parse(
                    "unsupported VLESS packetEncoding (expected xudp or none)".into(),
                ));
            }
        }
    }
    let flow = optional_text(query.values("flow").map(Some))
        .map_err(|_| ConfigError::Parse("conflicting VLESS flow parameters".into()))?;
    config.flow = optional_flow(flow)
        .map_err(|_| ConfigError::Validation("unsupported VLESS flow".into()))?
        .map(str::to_string);
    // Shadowrocket's exporter maps 1 to retired XTLS Direct and 2 to Vision.
    if let Some(xtls) = query.get("xtls") {
        let flow = match xtls.as_str() {
            "0" => None,
            "2" => Some("xtls-rprx-vision"),
            _ => return Err(ConfigError::Parse("unsupported VLESS xtls value".into())),
        };
        if config.flow.is_some() && config.flow.as_deref() != flow
            || flow.is_some() && !config.tls.enabled
        {
            return Err(ConfigError::Parse(
                "conflicting VLESS flow parameters".into(),
            ));
        }
        config.flow = flow.map(str::to_string);
    }
    config.encryption = query
        .get("encryption")
        .filter(|value| !value.trim().is_empty())
        .cloned();
    Ok(())
}
