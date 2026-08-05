use super::*;

/// geosite.dat / geoip.dat parsed at most once per `Router` build.
///
/// Every rule with a `geosite:`/`geoip:` condition used to re-read and
/// re-parse the whole multi-MB protobuf database (and re-compile every
/// geosite regex), so `Router` construction on a typical config burned a
/// full CPU core for >10 seconds at startup. The databases are now parsed
/// once into a per-code index, and only codes actually referenced by the
/// configuration have their regexes compiled / CIDRs decoded.
pub(crate) struct GeoAssets {
    geosite: Option<std::collections::HashMap<String, IndexedGeosite>>,
    geoip: Option<std::collections::HashMap<String, Vec<ipnet::IpNet>>>,
}

/// Decoded geosite category in the per-code index.
struct IndexedGeosite {
    domains: Vec<GeositeDomain>,
    /// Per-domain attribute keys (original case), parallel to `domains`.
    /// Decoded only when a referenced code selects this category with an
    /// `@attr` filter, so plain categories never pay the memory for it.
    attrs: Option<Vec<Vec<String>>>,
}

/// dae `strings.Cut(code, "@")` semantics: everything after the FIRST `@`
/// is the attribute selector verbatim — a second `@` stays inside it and
/// simply matches no attribute key (zero-match warn at expansion).
fn split_geosite_code(code: &str) -> (String, Option<String>) {
    match code.split_once('@') {
        Some((base, attr)) => (base.to_string(), Some(attr.to_string())),
        None => (code.to_string(), None),
    }
}

impl GeoAssets {
    pub(crate) fn load(rules: &[RoutingRule]) -> Self {
        use std::collections::HashSet;
        let mut geosite_codes: HashSet<String> = HashSet::new();
        let mut geoip_codes: HashSet<String> = HashSet::new();
        for rule in rules {
            geosite_codes.extend(
                rule.condition
                    .geosite
                    .iter()
                    .map(|c| c.trim().to_lowercase())
                    .filter(|c| !c.is_empty()),
            );
            geoip_codes.extend(
                rule.condition
                    .geo_ip
                    .iter()
                    .map(|c| c.trim().to_lowercase())
                    .filter(|c| !c.is_empty() && c != "private"),
            );
        }

        let geosite = if geosite_codes.is_empty() {
            None
        } else {
            load_geosite_index(&geosite_codes)
        };
        let geoip = if geoip_codes.is_empty() {
            None
        } else {
            load_geoip_index(&geoip_codes)
        };
        Self { geosite, geoip }
    }

    /// Load GeoAssets from explicit code sets (for DNS routing).
    pub(crate) fn load_codes(
        geosite_codes: &std::collections::HashSet<String>,
        geoip_codes: &std::collections::HashSet<String>,
    ) -> Self {
        let geosite = if geosite_codes.is_empty() {
            None
        } else {
            load_geosite_index(geosite_codes)
        };
        let geoip = if geoip_codes.is_empty() {
            None
        } else {
            load_geoip_index(geoip_codes)
        };
        Self { geosite, geoip }
    }

    /// Expand geosite codes into compiled domain matchers, cloned from the
    /// shared per-code index (`Regex` clones are cheap Arc bumps). A
    /// `category@attr` code filters the category down to entries carrying
    /// that attribute key (dae semantics: key presence, case-insensitive).
    pub(crate) fn geosite_domains(&self, codes: &[String]) -> Vec<GeositeDomain> {
        let mut out = Vec::new();
        if codes.is_empty() {
            return out;
        }
        match &self.geosite {
            Some(index) => {
                for code in codes {
                    let code = code.trim().to_lowercase();
                    let (base, attr) = split_geosite_code(&code);
                    let before = out.len();
                    if let Some(cat) = index.get(&base) {
                        match (&attr, &cat.attrs) {
                            (None, _) => out.extend(cat.domains.iter().cloned()),
                            (Some(attr), Some(attrs)) => {
                                out.extend(
                                    cat.domains
                                        .iter()
                                        .zip(attrs.iter())
                                        .filter(|(_, keys)| {
                                            keys.iter().any(|k| k.eq_ignore_ascii_case(attr))
                                        })
                                        .map(|(d, _)| d.clone()),
                                );
                            }
                            // Index built without attrs for this base means no
                            // referenced code asked for them — a same-build
                            // query with @attr can only come from a split/merge
                            // mismatch; treat as zero matches (warned below).
                            (Some(_), None) => {}
                        }
                    }
                    if out.len() == before {
                        // A code that expands to nothing silently disables its
                        // rule (unknown category, or an `@attr` no entry of the
                        // category carries) — never stay silent about that.
                        tracing::warn!(
                            code,
                            "geosite code expanded to zero matchers; rule will never match"
                        );
                    }
                }
                tracing::debug!("expanded geosite codes into {} domain matchers", out.len());
            }
            None => {
                tracing::warn!(
                    "geosite.dat unavailable; geosite conditions {:?} match nothing",
                    codes
                );
            }
        }
        out
    }

    /// Expand geoip codes into CIDR nets. `private` is built in and never
    /// touches geoip.dat; other codes come from the shared index.
    pub(crate) fn geoip_nets(&self, codes: &[String]) -> Vec<ipnet::IpNet> {
        let mut nets = Vec::new();
        for code in codes {
            let code = code.trim();
            if code.eq_ignore_ascii_case("private") {
                const PRIVATE_CIDRS: &[&str] = &[
                    "10.0.0.0/8",
                    "100.64.0.0/10",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "172.16.0.0/12",
                    "192.0.0.0/24",
                    "192.0.2.0/24",
                    "192.88.99.0/24",
                    "192.168.0.0/16",
                    "198.18.0.0/15",
                    "198.51.100.0/24",
                    "203.0.113.0/24",
                    "224.0.0.0/4",
                    "240.0.0.0/4",
                    "255.255.255.255/32",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10",
                ];
                for cidr in PRIVATE_CIDRS {
                    if let Ok(net) = cidr.parse() {
                        nets.push(net);
                    }
                }
                continue;
            }
            match &self.geoip {
                Some(index) => {
                    if let Some(v) = index.get(&code.to_lowercase()) {
                        nets.extend(v.iter().cloned());
                    }
                }
                None => {
                    tracing::warn!(
                        "geoip.dat unavailable; geoip condition '{}' matches nothing",
                        code
                    );
                }
            }
        }
        if !nets.is_empty() {
            tracing::debug!("expanded geoip codes into {} CIDRs", nets.len());
        }
        nets
    }
}

fn load_geosite_index(
    codes: &std::collections::HashSet<String>,
) -> Option<std::collections::HashMap<String, IndexedGeosite>> {
    let path = find_geosite_dat()?;
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("failed to read {}: {}", path.display(), e);
            return None;
        }
    };
    match parse_geosite_index(&data, codes) {
        Ok(index) => Some(index),
        Err(e) => {
            tracing::warn!("failed to parse {}: {}", path.display(), e);
            None
        }
    }
}

/// Locate geosite.dat for tooling queries (`honk-tool geosite`): the
/// explicit `--file` path wins at the call site; this is the fallback search
/// (current directory, then the dae asset locations).
pub fn find_geosite_dat() -> Option<std::path::PathBuf> {
    const CANDIDATES: &[&str] = &[
        "./geosite.dat",
        "/usr/local/share/dae/geosite.dat",
        "/usr/share/dae/geosite.dat",
        "/etc/dae/geosite.dat",
    ];
    if let Ok(asset) = std::env::var("DAE_LOCATION_ASSET") {
        let p = std::path::Path::new(&asset).join("geosite.dat");
        if p.is_file() {
            return Some(p);
        }
    }
    for c in CANDIDATES {
        let p = std::path::Path::new(c);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Parse geosite.dat once into a per-code index. Only codes in `codes`
/// (lowercased) have their domain entries decoded — in particular, regexes
/// are compiled at most once per Router build, and only for referenced codes.
/// Codes carrying an `@attr` selector index their base category with
/// per-entry attribute keys so expansion can filter on them.
fn parse_geosite_index(
    data: &[u8],
    codes: &std::collections::HashSet<String>,
) -> anyhow::Result<std::collections::HashMap<String, IndexedGeosite>> {
    use std::collections::HashSet;
    let mut bases: HashSet<String> = HashSet::with_capacity(codes.len());
    let mut attr_bases: HashSet<String> = HashSet::new();
    for c in codes {
        let (base, attr) = split_geosite_code(&c.trim().to_lowercase());
        if attr.is_some() {
            attr_bases.insert(base.clone());
        }
        bases.insert(base);
    }

    let mut decoder = ProtoDecoder::new(data);
    let mut index: std::collections::HashMap<String, IndexedGeosite> =
        std::collections::HashMap::new();

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        if tag != 1 {
            decoder.skip_field(wire)?;
            continue;
        }
        let entry = decoder.read_len_delimited()?;
        let (code, raw_domains) = split_geosite_entry(entry)?;
        let Some(code) = code else { continue };
        let code = code.to_lowercase();
        if !bases.contains(&code) {
            continue;
        }
        let keep_attrs = attr_bases.contains(&code);
        let mut domains = Vec::with_capacity(raw_domains.len());
        let mut attrs = keep_attrs.then(|| Vec::with_capacity(raw_domains.len()));
        for raw in raw_domains {
            match parse_geosite_domain(raw) {
                Ok(Some((d, keys))) => {
                    domains.push(d);
                    if let Some(attrs) = &mut attrs {
                        attrs.push(keys);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("skipping invalid geosite entry in '{}': {}", code, e);
                }
            }
        }
        index.insert(code, IndexedGeosite { domains, attrs });
    }

    Ok(index)
}

/// Split a Geosite protobuf entry into its country code and the raw
/// (still-encoded) domain messages, so domain decoding only happens for
/// codes the configuration actually references.
fn split_geosite_entry(data: &[u8]) -> anyhow::Result<(Option<String>, Vec<&[u8]>)> {
    let mut decoder = ProtoDecoder::new(data);
    let mut country_code: Option<String> = None;
    let mut raw_domains = Vec::new();

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        match tag {
            1 => {
                country_code =
                    Some(String::from_utf8_lossy(decoder.read_len_delimited()?).to_string());
            }
            2 => raw_domains.push(decoder.read_len_delimited()?),
            _ => decoder.skip_field(wire)?,
        }
    }

    Ok((country_code, raw_domains))
}

/// Decode one geosite Domain message into its matcher plus attribute keys
/// (tag 3, v2ray `Domain_Attribute`; only the key matters for routing —
/// dae filters `category@attr` by key presence, case-insensitively).
fn parse_geosite_domain(data: &[u8]) -> anyhow::Result<Option<(GeositeDomain, Vec<String>)>> {
    let mut decoder = ProtoDecoder::new(data);
    let mut dtype: Option<i32> = None;
    let mut value: Option<String> = None;
    let mut attrs = Vec::new();

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        match tag {
            1 => dtype = Some(decoder.read_varint()? as i32),
            2 => value = Some(String::from_utf8_lossy(decoder.read_len_delimited()?).to_string()),
            3 => attrs.push(parse_domain_attribute(decoder.read_len_delimited()?)?.0),
            _ => decoder.skip_field(wire)?,
        }
    }

    let value = value.ok_or_else(|| anyhow::anyhow!("geosite domain missing value"))?;
    let domain = match dtype {
        Some(0) => GeositeDomain::Keyword(value),
        Some(1) => GeositeDomain::Regex(
            Regex::new(&value).map_err(|e| anyhow::anyhow!("invalid geosite regex: {}", e))?,
        ),
        Some(2) => GeositeDomain::Domain(value),
        Some(3) => GeositeDomain::Full(value),
        _ => return Ok(None),
    };
    Ok(Some((domain, attrs)))
}

/// v2ray `Domain_Attribute { string key = 1; bool bool_value = 2; int64
/// typed_value = 3 }` — returns the key and the bool value when present.
fn parse_domain_attribute(data: &[u8]) -> anyhow::Result<(String, Option<bool>)> {
    let mut decoder = ProtoDecoder::new(data);
    let mut key: Option<String> = None;
    let mut bool_value: Option<bool> = None;

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        match tag {
            1 => key = Some(String::from_utf8_lossy(decoder.read_len_delimited()?).to_string()),
            2 => bool_value = Some(decoder.read_varint()? != 0),
            _ => decoder.skip_field(wire)?,
        }
    }

    let key = key.ok_or_else(|| anyhow::anyhow!("geosite attribute missing key"))?;
    Ok((key, bool_value))
}

/// Expand `geoip:<code>` to CIDRs. `geoip:private` uses a built-in list.
fn load_geoip_index(
    codes: &std::collections::HashSet<String>,
) -> Option<std::collections::HashMap<String, Vec<ipnet::IpNet>>> {
    let path = find_geoip_dat()?;
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("failed to read {}: {}", path.display(), e);
            return None;
        }
    };
    match parse_geoip_index(&data, codes) {
        Ok(index) => Some(index),
        Err(e) => {
            tracing::warn!("failed to parse {}: {}", path.display(), e);
            None
        }
    }
}

/// Locate geoip.dat for tooling queries (`honk-tool geoip`); see
/// [`find_geosite_dat`].
pub fn find_geoip_dat() -> Option<std::path::PathBuf> {
    const CANDIDATES: &[&str] = &[
        "./geoip.dat",
        "/usr/local/share/dae/geoip.dat",
        "/usr/share/dae/geoip.dat",
        "/etc/dae/geoip.dat",
    ];
    if let Ok(asset) = std::env::var("DAE_LOCATION_ASSET") {
        let p = std::path::Path::new(&asset).join("geoip.dat");
        if p.is_file() {
            return Some(p);
        }
    }
    for c in CANDIDATES {
        let p = std::path::Path::new(c);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Parse geoip.dat once into a per-code index. Only codes in `codes`
/// (lowercased) have their CIDR entries decoded.
fn parse_geoip_index(
    data: &[u8],
    codes: &std::collections::HashSet<String>,
) -> anyhow::Result<std::collections::HashMap<String, Vec<ipnet::IpNet>>> {
    let mut decoder = ProtoDecoder::new(data);
    let mut index: std::collections::HashMap<String, Vec<ipnet::IpNet>> =
        std::collections::HashMap::new();

    // GeoIPList has only field 1 (repeated GeoIP entry).
    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        if tag != 1 {
            decoder.skip_field(wire)?;
            continue;
        }
        let entry = decoder.read_len_delimited()?;
        if let Some((code, entry_nets)) = parse_geoip_entry(entry, codes)? {
            index.insert(code, entry_nets);
        }
    }

    Ok(index)
}

fn parse_geoip_entry(
    data: &[u8],
    codes: &std::collections::HashSet<String>,
) -> anyhow::Result<Option<(String, Vec<ipnet::IpNet>)>> {
    let mut decoder = ProtoDecoder::new(data);
    let mut country_code: Option<String> = None;
    let mut raw_cidrs: Vec<&[u8]> = Vec::new();

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        match tag {
            1 => {
                country_code =
                    Some(String::from_utf8_lossy(decoder.read_len_delimited()?).to_string());
            }
            2 => raw_cidrs.push(decoder.read_len_delimited()?),
            _ => decoder.skip_field(wire)?,
        }
    }

    let Some(code) = country_code.map(|s| s.to_lowercase()) else {
        return Ok(None);
    };
    if !codes.contains(&code) {
        return Ok(None);
    }
    let mut cidrs = Vec::with_capacity(raw_cidrs.len());
    for raw in raw_cidrs {
        if let Some(net) = parse_cidr(raw)? {
            cidrs.push(net);
        }
    }
    Ok(Some((code, cidrs)))
}

fn parse_cidr(data: &[u8]) -> anyhow::Result<Option<ipnet::IpNet>> {
    let mut decoder = ProtoDecoder::new(data);
    let mut ip_bytes: Option<&[u8]> = None;
    let mut prefix: Option<u32> = None;

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        match tag {
            1 => ip_bytes = Some(decoder.read_len_delimited()?),
            2 => prefix = Some(decoder.read_varint()? as u32),
            _ => decoder.skip_field(wire)?,
        }
    }

    let ip_bytes = ip_bytes.ok_or_else(|| anyhow::anyhow!("CIDR missing ip"))?;
    let prefix = prefix.ok_or_else(|| anyhow::anyhow!("CIDR missing prefix"))?;
    let ip: IpAddr = match ip_bytes.len() {
        4 => std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]).into(),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(ip_bytes);
            std::net::Ipv6Addr::from(octets).into()
        }
        _ => anyhow::bail!("invalid ip length {}", ip_bytes.len()),
    };
    let prefix_u8 = prefix
        .try_into()
        .map_err(|_| anyhow::anyhow!("CIDR prefix {} out of range", prefix))?;
    let net = ipnet::IpNet::new(ip, prefix_u8)?;
    // Skip default routes: they would match every destination and shadow real rules.
    if net.prefix_len() == 0 {
        return Ok(None);
    }
    Ok(Some(net))
}

struct ProtoDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ProtoDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn read_byte(&mut self) -> anyhow::Result<u8> {
        if self.pos >= self.data.len() {
            anyhow::bail!("unexpected end of protobuf data");
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_varint(&mut self) -> anyhow::Result<u64> {
        let mut value: u64 = 0;
        let mut shift = 0;
        loop {
            let b = self.read_byte()?;
            value |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                anyhow::bail!("varint overflow");
            }
        }
    }

    fn read_tag(&mut self) -> anyhow::Result<(u32, u8)> {
        let tag = self.read_varint()?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u8;
        Ok((field_number, wire_type))
    }

    fn read_len_delimited(&mut self) -> anyhow::Result<&'a [u8]> {
        let len = self.read_varint()? as usize;
        if self.pos + len > self.data.len() {
            anyhow::bail!("length-delimited field exceeds data");
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn skip_field(&mut self, wire_type: u8) -> anyhow::Result<()> {
        match wire_type {
            0 => {
                // varint
                self.read_varint()?;
            }
            2 => {
                // length-delimited
                let len = self.read_varint()? as usize;
                if self.pos + len > self.data.len() {
                    anyhow::bail!("skip length exceeds data");
                }
                self.pos += len;
            }
            5 => {
                // 32-bit
                if self.pos + 4 > self.data.len() {
                    anyhow::bail!("unexpected end skipping 32-bit");
                }
                self.pos += 4;
            }
            1 => {
                // 64-bit
                if self.pos + 8 > self.data.len() {
                    anyhow::bail!("unexpected end skipping 64-bit");
                }
                self.pos += 8;
            }
            _ => anyhow::bail!("unknown wire type {}", wire_type),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Read-only dat scan API for honk-tool.
//
// The routing hot path (`GeoAssets`) decodes only the codes a config
// references (plus attribute keys for `@attr`-selected categories). `honk-tool geosite|geoip` needs a
// full-content scan instead, so this block re-decodes the same protobuf wire
// format into owned, tool-oriented structures. Nothing here feeds routing:
// attribute decoding cannot alter match behavior.
// ---------------------------------------------------------------------------

/// Wire type of a decoded geosite domain entry (v2ray `Domain.Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeositeKind {
    Keyword,
    Regex,
    Domain,
    Full,
}

impl GeositeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keyword => "keyword",
            Self::Regex => "regexp",
            Self::Domain => "domain",
            Self::Full => "full",
        }
    }
}

/// One decoded geosite domain entry; `value` is kept verbatim (regexes are
/// compiled only on demand by [`GeositeScan::find`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeositeEntry {
    pub kind: GeositeKind,
    pub value: String,
    /// `@attr` names from the v2ray geosite `Domain.attribute` field;
    /// `!name` marks an attribute whose bool_value is explicitly false.
    pub attrs: Vec<String>,
}

/// A geosite.dat category with its decoded entries.
#[derive(Debug, Clone)]
pub struct GeositeCategory {
    pub code: String,
    pub entries: Vec<GeositeEntry>,
}

/// Full-content scan of a geosite.dat file.
#[derive(Debug, Clone)]
pub struct GeositeScan {
    categories: Vec<GeositeCategory>,
}

impl GeositeScan {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
        let categories = parse_geosite_full(&data)
            .map_err(|e| anyhow::anyhow!("failed to parse {}: {}", path.display(), e))?;
        Ok(Self { categories })
    }

    pub fn categories(&self) -> &[GeositeCategory] {
        &self.categories
    }

    /// Category lookup by exact code, case-insensitive.
    pub fn category(&self, code: &str) -> Option<&GeositeCategory> {
        self.categories
            .iter()
            .find(|c| c.code.eq_ignore_ascii_case(code))
    }

    /// Reverse lookup: every `(category, entry)` whose matcher semantics
    /// would match `domain` (mirrors `GeositeMatcher`: Full is a
    /// case-insensitive exact match, Domain a dot-boundary suffix match,
    /// Keyword a case-sensitive substring, Regex against the raw domain).
    pub fn find<'a>(&'a self, domain: &str) -> Vec<(&'a GeositeCategory, &'a GeositeEntry)> {
        let mut out = Vec::new();
        for cat in &self.categories {
            for entry in &cat.entries {
                if entry_matches(entry, domain) {
                    out.push((cat, entry));
                }
            }
        }
        out
    }
}

fn entry_matches(entry: &GeositeEntry, domain: &str) -> bool {
    match entry.kind {
        GeositeKind::Full => entry.value.eq_ignore_ascii_case(domain),
        GeositeKind::Domain => {
            let host = domain.to_lowercase();
            let suffix = entry.value.to_lowercase();
            host == suffix
                || host
                    .strip_suffix(&suffix)
                    .is_some_and(|head| head.ends_with('.'))
        }
        GeositeKind::Keyword => domain.contains(&entry.value),
        GeositeKind::Regex => Regex::new(&entry.value).is_ok_and(|re| re.is_match(domain)),
    }
}

fn parse_geosite_full(data: &[u8]) -> anyhow::Result<Vec<GeositeCategory>> {
    let mut decoder = ProtoDecoder::new(data);
    let mut out = Vec::new();

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        if tag != 1 {
            decoder.skip_field(wire)?;
            continue;
        }
        let entry = decoder.read_len_delimited()?;
        let (code, raw_domains) = split_geosite_entry(entry)?;
        let Some(code) = code else { continue };
        let mut entries = Vec::with_capacity(raw_domains.len());
        for raw in raw_domains {
            if let Some(e) = parse_geosite_domain_scanned(raw)? {
                entries.push(e);
            }
        }
        out.push(GeositeCategory { code, entries });
    }

    Ok(out)
}

/// Decode one geosite Domain message for tooling, keeping the raw value and
/// display-decorated attributes (`!name` marks an explicitly-false bool).
fn parse_geosite_domain_scanned(data: &[u8]) -> anyhow::Result<Option<GeositeEntry>> {
    let mut decoder = ProtoDecoder::new(data);
    let mut dtype: Option<i32> = None;
    let mut value: Option<String> = None;
    let mut attrs = Vec::new();

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        match tag {
            1 => dtype = Some(decoder.read_varint()? as i32),
            2 => value = Some(String::from_utf8_lossy(decoder.read_len_delimited()?).to_string()),
            3 => {
                let (key, bool_value) = parse_domain_attribute(decoder.read_len_delimited()?)?;
                attrs.push(match bool_value {
                    Some(false) => format!("!{key}"),
                    _ => key,
                });
            }
            _ => decoder.skip_field(wire)?,
        }
    }

    let value = value.ok_or_else(|| anyhow::anyhow!("geosite domain missing value"))?;
    let kind = match dtype {
        Some(0) => GeositeKind::Keyword,
        Some(1) => GeositeKind::Regex,
        Some(2) => GeositeKind::Domain,
        Some(3) => GeositeKind::Full,
        _ => return Ok(None),
    };
    Ok(Some(GeositeEntry { kind, value, attrs }))
}

/// A geoip.dat code with its decoded CIDRs.
#[derive(Debug, Clone)]
pub struct GeoipCategory {
    pub code: String,
    pub cidrs: Vec<ipnet::IpNet>,
}

/// Full-content scan of a geoip.dat file.
#[derive(Debug, Clone)]
pub struct GeoipScan {
    categories: Vec<GeoipCategory>,
}

impl GeoipScan {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
        let categories = parse_geoip_full(&data)
            .map_err(|e| anyhow::anyhow!("failed to parse {}: {}", path.display(), e))?;
        Ok(Self { categories })
    }

    pub fn categories(&self) -> &[GeoipCategory] {
        &self.categories
    }

    /// Code lookup, case-insensitive.
    pub fn category(&self, code: &str) -> Option<&GeoipCategory> {
        self.categories
            .iter()
            .find(|c| c.code.eq_ignore_ascii_case(code))
    }

    /// Longest-prefix match: every `(code, cidr)` pair sharing the longest
    /// prefix that contains `ip` (ties across codes are all returned).
    pub fn lookup(&self, ip: IpAddr) -> Vec<(&GeoipCategory, ipnet::IpNet)> {
        let mut best: Option<u8> = None;
        let mut out = Vec::new();
        for cat in &self.categories {
            for net in &cat.cidrs {
                if !net.contains(&ip) {
                    continue;
                }
                let plen = net.prefix_len();
                match best {
                    Some(b) if b > plen => {}
                    Some(b) if b == plen => out.push((cat, *net)),
                    _ => {
                        best = Some(plen);
                        out.clear();
                        out.push((cat, *net));
                    }
                }
            }
        }
        out
    }
}

fn parse_geoip_full(data: &[u8]) -> anyhow::Result<Vec<GeoipCategory>> {
    let mut decoder = ProtoDecoder::new(data);
    let mut out = Vec::new();

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        if tag != 1 {
            decoder.skip_field(wire)?;
            continue;
        }
        let entry = decoder.read_len_delimited()?;
        let (code, raw_cidrs) = split_geoip_entry(entry)?;
        let Some(code) = code else { continue };
        let mut cidrs = Vec::with_capacity(raw_cidrs.len());
        for raw in raw_cidrs {
            if let Some(net) = parse_cidr(raw)? {
                cidrs.push(net);
            }
        }
        out.push(GeoipCategory { code, cidrs });
    }

    Ok(out)
}

fn split_geoip_entry(data: &[u8]) -> anyhow::Result<(Option<String>, Vec<&[u8]>)> {
    let mut decoder = ProtoDecoder::new(data);
    let mut country_code: Option<String> = None;
    let mut raw_cidrs: Vec<&[u8]> = Vec::new();

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        match tag {
            1 => {
                country_code =
                    Some(String::from_utf8_lossy(decoder.read_len_delimited()?).to_string());
            }
            2 => raw_cidrs.push(decoder.read_len_delimited()?),
            _ => decoder.skip_field(wire)?,
        }
    }

    Ok((country_code, raw_cidrs))
}

#[cfg(test)]
mod scan_tests {
    use super::*;

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

    fn domain_msg(dtype: i32, value: &str, attrs: &[(&str, Option<bool>)]) -> Vec<u8> {
        let mut m = Vec::new();
        push_varint_field(1, dtype as u64, &mut m);
        push_len_delim(2, value.as_bytes(), &mut m);
        for (key, bv) in attrs {
            let mut a = Vec::new();
            push_len_delim(1, key.as_bytes(), &mut a);
            if let Some(b) = bv {
                push_varint_field(2, u64::from(*b), &mut a);
            }
            push_len_delim(3, &a, &mut m);
        }
        m
    }

    fn geosite_dat(categories: &[(&str, Vec<Vec<u8>>)]) -> Vec<u8> {
        let mut dat = Vec::new();
        for (code, domains) in categories {
            let mut e = Vec::new();
            push_len_delim(1, code.as_bytes(), &mut e);
            for d in domains {
                push_len_delim(2, d, &mut e);
            }
            push_len_delim(1, &e, &mut dat);
        }
        dat
    }

    type CidrSpec<'a> = (&'a [u8], u32);

    fn geoip_dat(categories: &[(&str, Vec<CidrSpec>)]) -> Vec<u8> {
        let mut dat = Vec::new();
        for (code, cidrs) in categories {
            let mut e = Vec::new();
            push_len_delim(1, code.as_bytes(), &mut e);
            for (ip, prefix) in cidrs {
                let mut c = Vec::new();
                push_len_delim(1, ip, &mut c);
                push_varint_field(2, u64::from(*prefix), &mut c);
                push_len_delim(2, &c, &mut e);
            }
            push_len_delim(1, &e, &mut dat);
        }
        dat
    }

    fn scan_geosite(dat: &[u8]) -> GeositeScan {
        GeositeScan {
            categories: parse_geosite_full(dat).unwrap(),
        }
    }

    #[test]
    fn decodes_entry_attributes() {
        let dat = geosite_dat(&[(
            "TEST",
            vec![
                domain_msg(
                    2,
                    "example.com",
                    &[("cn", Some(true)), ("ads", Some(false))],
                ),
                domain_msg(3, "plain.example", &[]),
            ],
        )]);
        let scan = scan_geosite(&dat);
        let cat = scan.category("test").unwrap();
        assert_eq!(cat.entries.len(), 2);
        assert_eq!(cat.entries[0].kind, GeositeKind::Domain);
        assert_eq!(cat.entries[0].attrs, vec!["cn", "!ads"]);
        assert_eq!(cat.entries[1].kind, GeositeKind::Full);
        assert!(cat.entries[1].attrs.is_empty());
    }

    #[test]
    fn find_mirrors_routing_match_semantics() {
        let dat = geosite_dat(&[(
            "MIX",
            vec![
                domain_msg(3, "exact.example", &[]),
                domain_msg(2, "suffix.example", &[]),
                domain_msg(0, "KeyWord", &[]),
                domain_msg(1, "^re-[0-9]+\\.example$", &[]),
            ],
        )]);
        let scan = scan_geosite(&dat);
        let hit = |d: &str| scan.find(d).len();

        assert_eq!(hit("EXACT.example"), 1); // full: case-insensitive exact
        assert_eq!(hit("www.exact.example"), 0);
        assert_eq!(hit("a.suffix.example"), 1); // domain: dot-boundary suffix
        assert_eq!(hit("notasuffix.example"), 0);
        assert_eq!(hit("xKeyWordx"), 1); // keyword: case-sensitive substring
        assert_eq!(hit("xkeywordx"), 0);
        assert_eq!(hit("re-42.example"), 1); // regex: real match
        assert_eq!(hit("re-x.example"), 0);
    }

    #[test]
    fn geoip_lookup_is_longest_prefix() {
        let dat = geoip_dat(&[
            ("BROAD", vec![(&[1, 0, 0, 0], 8)]),
            ("NARROW", vec![(&[1, 2, 3, 0], 24)]),
            (
                "V6",
                vec![(&[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32)],
            ),
        ]);
        let scan = GeoipScan {
            categories: parse_geoip_full(&dat).unwrap(),
        };

        let hits = scan.lookup("1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.code, "NARROW");

        let hits = scan.lookup("1.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.code, "BROAD");

        let hits = scan.lookup("2001::1".parse::<IpAddr>().unwrap());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.code, "V6");

        assert!(scan.lookup("9.9.9.9".parse::<IpAddr>().unwrap()).is_empty());
    }

    fn assets_for(dat: &[u8], codes: &[&str]) -> GeoAssets {
        let set: std::collections::HashSet<String> = codes.iter().map(|c| c.to_string()).collect();
        GeoAssets {
            geosite: Some(parse_geosite_index(dat, &set).unwrap()),
            geoip: None,
        }
    }

    fn attr_fixture() -> Vec<u8> {
        geosite_dat(&[
            (
                "SHOP",
                vec![
                    domain_msg(2, "mall.example", &[("cn", Some(true))]),
                    domain_msg(2, "global.example", &[]),
                    domain_msg(3, "exact.shop", &[("CN", Some(true)), ("ads", None)]),
                ],
            ),
            ("PLAIN", vec![domain_msg(2, "plain.example", &[])]),
        ])
    }

    #[test]
    fn attr_filter_selects_only_carrying_entries() {
        let dat = attr_fixture();
        let assets = assets_for(&dat, &["shop@cn"]);

        let filtered = assets.geosite_domains(&["shop@cn".to_string()]);
        assert_eq!(filtered.len(), 2);
        let matcher = GeositeMatcher::build(&filtered);
        assert!(matcher.matches("www.mall.example"));
        assert!(matcher.matches("exact.shop"));
        assert!(!matcher.matches("global.example"));

        // EqualFold: the query case does not matter, nor does the key case.
        let folded = assets.geosite_domains(&["SHOP@Cn".to_string()]);
        assert_eq!(folded.len(), 2);
    }

    #[test]
    fn no_attr_code_behavior_unchanged() {
        let dat = attr_fixture();
        let assets = assets_for(&dat, &["shop", "plain"]);

        let all = assets.geosite_domains(&["shop".to_string()]);
        assert_eq!(all.len(), 3);
        // Plain-only reference: the index must not materialize attr vectors.
        let index = assets.geosite.as_ref().unwrap();
        assert!(index.get("shop").unwrap().attrs.is_none());
        assert!(index.get("plain").unwrap().attrs.is_none());
    }

    #[test]
    fn mixed_plain_and_attr_references_share_one_index() {
        let dat = attr_fixture();
        let assets = assets_for(&dat, &["shop", "shop@cn"]);
        assert!(assets.geosite.as_ref().unwrap()["shop"].attrs.is_some());

        assert_eq!(assets.geosite_domains(&["shop".to_string()]).len(), 3);
        assert_eq!(assets.geosite_domains(&["shop@cn".to_string()]).len(), 2);
    }

    #[test]
    fn unknown_attr_and_multi_at_expand_to_zero() {
        let dat = attr_fixture();
        let assets = assets_for(&dat, &["shop@nope", "shop@cn@extra", "noshop"]);

        // dae Cut semantics: the attr is everything after the FIRST '@', so
        // "cn@extra" matches no attribute key — like any unknown selector.
        assert!(
            assets
                .geosite_domains(&["shop@nope".to_string()])
                .is_empty()
        );
        assert!(
            assets
                .geosite_domains(&["shop@cn@extra".to_string()])
                .is_empty()
        );
        assert!(assets.geosite_domains(&["noshop".to_string()]).is_empty());
    }

    /// Real-dat cross-check: routing expansion of `category@attr` must select
    /// exactly the entries `GeositeScan` reports as carrying that attribute
    /// (what `honk-tool geosite show <category> --attr <attr>` lists).
    /// Skipped when no geosite.dat is available.
    ///
    /// Note: a `!key` attribute (negative marker, stored verbatim in the dat)
    /// never EqualFold-matches `key` — dae semantics are plain key equality,
    /// so `didi@cn` correctly excludes `@!cn` entries.
    #[test]
    fn attr_expansion_matches_tool_scan_on_real_dat() {
        let Some(path) = find_geosite_dat() else {
            eprintln!("no geosite.dat available; skipping");
            return;
        };
        let scan = GeositeScan::load(&path).unwrap();
        // Pick a category with a positive attribute key so the assertion is
        // meaningful on any real dat.
        let Some((cat, attr)) = scan.categories().iter().find_map(|c| {
            c.entries
                .iter()
                .find_map(|e| e.attrs.iter().find(|a| !a.starts_with('!')).map(|a| (c, a)))
        }) else {
            eprintln!("geosite.dat has no positively-attributed entries; skipping");
            return;
        };

        let tool_count = cat
            .entries
            .iter()
            .filter(|e| e.attrs.iter().any(|a| a.eq_ignore_ascii_case(attr)))
            .count();
        assert!(tool_count > 0);

        let codes: std::collections::HashSet<String> =
            [format!("{}@{}", cat.code, attr)].into_iter().collect();
        let assets = GeoAssets::load_codes(&codes, &std::collections::HashSet::new());
        let expanded = assets.geosite_domains(&[format!("{}@{}", cat.code, attr)]);
        assert_eq!(expanded.len(), tool_count, "routing vs tool attr count");
    }
}
