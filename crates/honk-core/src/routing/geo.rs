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
    geosite: Option<std::collections::HashMap<String, Vec<GeositeDomain>>>,
    geoip: Option<std::collections::HashMap<String, Vec<ipnet::IpNet>>>,
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
    /// shared per-code index (`Regex` clones are cheap Arc bumps).
    pub(crate) fn geosite_domains(&self, codes: &[String]) -> Vec<GeositeDomain> {
        let mut out = Vec::new();
        if codes.is_empty() {
            return out;
        }
        match &self.geosite {
            Some(index) => {
                for code in codes {
                    if let Some(domains) = index.get(&code.trim().to_lowercase()) {
                        out.extend(domains.iter().cloned());
                    } else {
                        // A code that expands to nothing silently disables its
                        // rule (e.g. an `@attr` filter this geosite.dat does
                        // not materialize) — never stay silent about that.
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
) -> Option<std::collections::HashMap<String, Vec<GeositeDomain>>> {
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

fn find_geosite_dat() -> Option<std::path::PathBuf> {
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
fn parse_geosite_index(
    data: &[u8],
    codes: &std::collections::HashSet<String>,
) -> anyhow::Result<std::collections::HashMap<String, Vec<GeositeDomain>>> {
    let mut decoder = ProtoDecoder::new(data);
    let mut index: std::collections::HashMap<String, Vec<GeositeDomain>> =
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
        if !codes.contains(&code) {
            continue;
        }
        let mut domains = Vec::with_capacity(raw_domains.len());
        for raw in raw_domains {
            match parse_geosite_domain(raw) {
                Ok(Some(d)) => domains.push(d),
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("skipping invalid geosite entry in '{}': {}", code, e);
                }
            }
        }
        index.insert(code, domains);
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

fn parse_geosite_domain(data: &[u8]) -> anyhow::Result<Option<GeositeDomain>> {
    let mut decoder = ProtoDecoder::new(data);
    let mut dtype: Option<i32> = None;
    let mut value: Option<String> = None;

    while !decoder.is_empty() {
        let (tag, wire) = decoder.read_tag()?;
        match tag {
            1 => dtype = Some(decoder.read_varint()? as i32),
            2 => value = Some(String::from_utf8_lossy(decoder.read_len_delimited()?).to_string()),
            3 => decoder.skip_field(wire)?, // attributes
            _ => decoder.skip_field(wire)?,
        }
    }

    let value = value.ok_or_else(|| anyhow::anyhow!("geosite domain missing value"))?;
    Ok(match dtype {
        Some(0) => Some(GeositeDomain::Keyword(value)),
        Some(1) => {
            Some(GeositeDomain::Regex(Regex::new(&value).map_err(|e| {
                anyhow::anyhow!("invalid geosite regex: {}", e)
            })?))
        }
        Some(2) => Some(GeositeDomain::Domain(value)),
        Some(3) => Some(GeositeDomain::Full(value)),
        _ => None,
    })
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

fn find_geoip_dat() -> Option<std::path::PathBuf> {
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
