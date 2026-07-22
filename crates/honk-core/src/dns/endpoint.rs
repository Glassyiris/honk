//! Parse DNS upstream address strings into host/port/path/SNI.
//!
//! Config stores scheme-stripped fragments:
//! - `8.8.8.8:53`
//! - `dns.google:853`
//! - `dns.google/dns-query`
//! - `1.1.1.1:443/dns-query`

use std::net::{IpAddr, SocketAddr};

use honk_config::types::DnsProtocol;

/// Default DoH / DoH3 request path (RFC 8484).
pub const DEFAULT_DOH_PATH: &str = "/dns-query";

/// Parsed upstream endpoint used by the encrypted DNS transports.
#[derive(Debug, Clone)]
pub struct DnsEndpoint {
    pub host: String,
    pub port: u16,
    /// HTTP path for DoH/DoH3 (always starts with `/`).
    pub path: String,
    /// TLS/QUIC server name (SNI). Falls back to `host` when host is not an IP.
    pub sni: String,
}

impl DnsEndpoint {
    /// Parse `address` for `protocol`, applying default ports/paths and optional
    /// config-level `tls_server_name` override.
    pub fn parse(
        address: &str,
        protocol: DnsProtocol,
        tls_server_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        let address = address.trim();
        if address.is_empty() {
            anyhow::bail!("empty DNS upstream address");
        }

        let (hostport, path_raw) = split_hostport_path(address);
        let (host, port_opt) = split_host_port(hostport)?;

        let default_port = default_port(protocol);
        let port = port_opt.unwrap_or(default_port);

        let path = match protocol {
            DnsProtocol::Https | DnsProtocol::H3 => normalize_path(path_raw),
            _ => String::new(),
        };

        let sni = if let Some(sni) = tls_server_name.map(str::trim).filter(|s| !s.is_empty()) {
            sni.to_string()
        } else if host.parse::<IpAddr>().is_ok() {
            // IP literal — SNI still required by rustls; use the IP string.
            host.clone()
        } else {
            host.clone()
        };

        Ok(Self {
            host,
            port,
            path,
            sni,
        })
    }

    /// Resolve host → one `SocketAddr` via bootstrap (bypass-marked) DNS.
    ///
    /// Prefers IPv4 when both families are returned so broken dual-stack
    /// networks (common on gateways without working IPv6 egress) still dial.
    pub async fn resolve_addr(&self) -> anyhow::Result<SocketAddr> {
        let mut addrs = self.resolve_addrs().await?;
        addrs.pop().ok_or_else(|| {
            anyhow::anyhow!("bootstrap resolve '{}' returned no addresses", self.host)
        })
    }

    /// Resolve host → all candidate addresses (IPv4 preferred, then IPv6).
    ///
    /// Callers that dial should iterate this list rather than only the first
    /// address — `lookup_host` often returns unreachable AAAA first.
    pub async fn resolve_addrs(&self) -> anyhow::Result<Vec<SocketAddr>> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, self.port)]);
        }
        let ips = honk_outbound::bootstrap::resolve(&self.host)
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap resolve '{}': {}", self.host, e))?;
        if ips.is_empty() {
            anyhow::bail!("bootstrap resolve '{}' returned no addresses", self.host);
        }
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for ip in ips {
            let sa = SocketAddr::new(ip, self.port);
            if sa.is_ipv4() {
                v4.push(sa);
            } else {
                v6.push(sa);
            }
        }
        // IPv4 first: many hosts advertise AAAA but lack working v6 egress.
        v4.extend(v6);
        Ok(v4)
    }
}

fn default_port(protocol: DnsProtocol) -> u16 {
    match protocol {
        DnsProtocol::Udp | DnsProtocol::Tcp => 53,
        DnsProtocol::Tls | DnsProtocol::Quic => 853,
        DnsProtocol::Https | DnsProtocol::H3 => 443,
    }
}

fn normalize_path(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return DEFAULT_DOH_PATH.to_string();
    }
    if raw.starts_with('/') {
        raw.to_string()
    } else {
        format!("/{raw}")
    }
}

fn split_hostport_path(address: &str) -> (&str, &str) {
    // Prefer splitting on the first `/` that is not inside an IPv6 bracket.
    if let Some(bracket_end) = address.find(']') {
        let after_bracket = &address[bracket_end + 1..];
        if let Some(pos) = after_bracket.find('/') {
            return (&address[..bracket_end + 1 + pos], &after_bracket[pos..]);
        }
        return (address, "");
    }
    if let Some(pos) = address.find('/') {
        (&address[..pos], &address[pos..])
    } else {
        (address, "")
    }
}

fn split_host_port(hostport: &str) -> anyhow::Result<(String, Option<u16>)> {
    let hostport = hostport.trim();
    if let Some(rest) = hostport.strip_prefix('[') {
        // [ipv6] or [ipv6]:port
        let (inside, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("unclosed IPv6 bracket in '{hostport}'"))?;
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(
                p.parse::<u16>()
                    .map_err(|e| anyhow::anyhow!("invalid port in '{hostport}': {e}"))?,
            )
        } else if after.is_empty() {
            None
        } else {
            anyhow::bail!("junk after IPv6 address in '{hostport}'");
        };
        return Ok((inside.to_string(), port));
    }

    // host:port — only split when suffix is numeric (so "dns.google" stays intact).
    if let Some((host, port_s)) = hostport.rsplit_once(':')
        && !host.is_empty()
        && port_s.chars().all(|c| c.is_ascii_digit())
        && !port_s.is_empty()
    {
        let port: u16 = port_s
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid port in '{hostport}': {e}"))?;
        return Ok((host.to_string(), Some(port)));
    }
    Ok((hostport.to_string(), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dot_defaults() {
        let ep = DnsEndpoint::parse("dns.google", DnsProtocol::Tls, None).unwrap();
        assert_eq!(ep.host, "dns.google");
        assert_eq!(ep.port, 853);
        assert_eq!(ep.sni, "dns.google");
        assert!(ep.path.is_empty());
    }

    #[test]
    fn parse_doh_path_and_port() {
        let ep =
            DnsEndpoint::parse("cloudflare-dns.com/dns-query", DnsProtocol::Https, None).unwrap();
        assert_eq!(ep.host, "cloudflare-dns.com");
        assert_eq!(ep.port, 443);
        assert_eq!(ep.path, "/dns-query");
        assert_eq!(ep.sni, "cloudflare-dns.com");
    }

    #[test]
    fn parse_ip_with_port() {
        let ep = DnsEndpoint::parse("1.1.1.1:853", DnsProtocol::Tls, Some("cloudflare-dns.com"))
            .unwrap();
        assert_eq!(ep.host, "1.1.1.1");
        assert_eq!(ep.port, 853);
        assert_eq!(ep.sni, "cloudflare-dns.com");
    }

    #[test]
    fn parse_ipv6() {
        let ep = DnsEndpoint::parse("[2606:4700:4700::1111]:853", DnsProtocol::Tls, None).unwrap();
        assert_eq!(ep.host, "2606:4700:4700::1111");
        assert_eq!(ep.port, 853);
    }

    #[test]
    fn parse_h3_default_path() {
        let ep = DnsEndpoint::parse("dns.google", DnsProtocol::H3, None).unwrap();
        assert_eq!(ep.port, 443);
        assert_eq!(ep.path, "/dns-query");
    }
}
