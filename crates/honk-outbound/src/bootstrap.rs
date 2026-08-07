//! Bootstrap DNS resolution for proxy-server hostnames.
//!
//! Node dials must not depend on the regular DNS path: the system resolver
//! may itself be routed through honk (interception + DNS routing), so right
//! after a restart — before any node is reachable — resolving a proxy
//! server's domain can deadlock against the very nodes it is needed to
//! reach. dae solves this with `bootstrap_resolver`: a plain, direct DNS
//! server that honk queries itself on a bypass-marked socket.
//!
//! [`resolve`] checks the configured bootstrap resolver first and falls back
//! to the system resolver on any failure, so behavior is unchanged when no
//! `bootstrap_resolver` is configured.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::RwLock;
use std::time::Duration;

/// A direct DNS server used to resolve proxy-server hostnames.
#[derive(Debug, Clone, Copy)]
pub struct BootstrapResolver {
    server: SocketAddr,
    use_tcp: bool,
}

impl BootstrapResolver {
    /// Parse `8.8.8.8:53`, `udp://8.8.8.8:53` or `tcp://8.8.8.8:53`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (use_tcp, rest) = match s.split_once("://") {
            Some((scheme, rest)) => (scheme.eq_ignore_ascii_case("tcp"), rest),
            None => (false, s),
        };
        let server: SocketAddr = rest.parse().ok()?;
        Some(Self { server, use_tcp })
    }
}

static GLOBAL: RwLock<Option<BootstrapResolver>> = RwLock::new(None);

/// Install (or clear) the process-wide bootstrap resolver. Called by
/// honk-core at startup and on config reload.
pub fn set_global(resolver: Option<BootstrapResolver>) {
    *GLOBAL.write().unwrap() = resolver;
}

/// Snapshot the process-wide resolver for compatibility callers that do not
/// already own a configuration generation.
pub fn global() -> Option<BootstrapResolver> {
    match GLOBAL.read() {
        Ok(resolver) => *resolver,
        Err(poisoned) => *poisoned.into_inner(),
    }
}

/// The configured bootstrap resolver's server address, if any. Also used
/// as the `direct` node's probe/urltest target: a plain directly-reachable
/// DNS server is exactly what direct-egress latency should be measured
/// against.
pub fn global_server() -> Option<SocketAddr> {
    GLOBAL.read().unwrap().map(|r| r.server)
}

/// Resolve `host` to IP addresses, preferring the configured bootstrap
/// resolver (direct, bypass-marked) and falling back to the system resolver.
pub async fn resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    resolve_with(global(), host).await
}

/// Resolve with an explicit resolver snapshot.
///
/// Generation-owned callers use this path so a later [`set_global`] cannot
/// change the resolver selected by an in-flight or lazily initialized dial.
pub async fn resolve_with(
    resolver: Option<BootstrapResolver>,
    host: &str,
) -> io::Result<Vec<IpAddr>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if let Some(resolver) = resolver {
        match tokio::time::timeout(Duration::from_secs(3), resolver.query(host)).await {
            Ok(Ok(ips)) if !ips.is_empty() => return Ok(ips),
            Ok(Ok(_)) => {
                tracing::debug!("bootstrap resolver returned no records for '{}'", host)
            }
            Ok(Err(e)) => {
                tracing::debug!("bootstrap resolution of '{}' failed: {}", host, e)
            }
            Err(_) => {
                tracing::debug!("bootstrap resolution of '{}' timed out", host)
            }
        }
    }
    let addrs: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:0", host))
        .await?
        .map(|a| a.ip())
        .collect();
    Ok(addrs)
}

impl BootstrapResolver {
    /// Query A and AAAA records for `host` directly from the configured
    /// server over a bypass-marked socket.
    async fn query(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        if self.use_tcp {
            let ips_a = self.query_tcp(host, 1).await?;
            let ips_aaaa = self.query_tcp(host, 28).await.unwrap_or_default();
            Ok([ips_a, ips_aaaa].concat())
        } else {
            let ips_a = self.query_udp(host, 1).await?;
            let ips_aaaa = self.query_udp(host, 28).await.unwrap_or_default();
            Ok([ips_a, ips_aaaa].concat())
        }
    }

    async fn query_udp(&self, host: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
        parse_answers(&query_udp_raw(self.server, host, qtype).await?, qtype)
    }

    async fn query_tcp(&self, host: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
        parse_answers(&self.query_tcp_raw(host, qtype).await?, qtype)
    }

    /// Send a single query and return the raw response bytes.
    async fn query_raw(&self, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
        if self.use_tcp {
            self.query_tcp_raw(host, qtype).await
        } else {
            query_udp_raw(self.server, host, qtype).await
        }
    }

    async fn query_tcp_raw(&self, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = crate::util::connect_marked_addr(
            self.server,
            Some(honk_ebpf_common::DAE_BYPASS_MARK),
            Duration::from_secs(3),
        )
        .await?;
        let query = build_query(host, qtype);
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&query).await?;
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

/// One UDP query/response exchange with `server` over a bypass-marked socket.
async fn query_udp_raw(server: SocketAddr, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = crate::util::udp_marked_bind(bind).await?;
    socket.connect(server).await?;
    socket.send(&build_query(host, qtype)).await?;
    let mut buf = [0u8; 1500];
    let n = socket.recv(&mut buf).await?;
    Ok(buf[..n].to_vec())
}

/// First nameserver from /etc/resolv.conf (UDP, port 53). Used for record
/// lookups (e.g. ECH discovery) when no `bootstrap_resolver` is configured.
fn system_nameserver() -> Option<SocketAddr> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in contents.lines() {
        if let Some(rest) = line.trim().strip_prefix("nameserver")
            && let Ok(ip) = rest.trim().parse::<IpAddr>()
        {
            return Some(SocketAddr::new(ip, 53));
        }
    }
    None
}

/// DNS qtype for HTTPS service-binding records (RFC 9460).
const QTYPE_HTTPS: u16 = 65;
/// SVCB SvcParam key carrying the ECHConfigList.
const SVCB_KEY_ECH: u16 = 5;

/// Look up the ECHConfigList for `host` via DNS HTTPS records (RFC 9460).
///
/// Queries the configured bootstrap resolver, or the first system nameserver
/// when none is configured. Returns the ECHConfigList and the record TTL, or
/// `None` when no usable HTTPS record exists.
pub async fn query_ech_config(host: &str) -> io::Result<Option<(Vec<u8>, u32)>> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.parse::<IpAddr>().is_ok() {
        return Ok(None);
    }
    let resolver = *GLOBAL.read().unwrap();
    let msg = match resolver {
        Some(r) => r.query_raw(host, QTYPE_HTTPS).await?,
        None => {
            let Some(server) = system_nameserver() else {
                return Ok(None);
            };
            query_udp_raw(server, host, QTYPE_HTTPS).await?
        }
    };
    Ok(parse_https_rr_ech(&msg))
}

/// Extract the ECHConfigList and TTL from the first ServiceMode HTTPS RR in
/// a DNS response. AliasMode records (priority != 0) carry no SvcParams and
/// are skipped.
fn parse_https_rr_ech(msg: &[u8]) -> Option<(Vec<u8>, u32)> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(msg, pos).ok()?;
        pos = pos.checked_add(4)?;
    }
    for _ in 0..an {
        pos = skip_name(msg, pos).ok()?;
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return None;
        }
        if rtype == QTYPE_HTTPS
            && rdlen >= 3
            && let Some(ech) = parse_svcb_ech_param(&msg[pos..pos + rdlen])
        {
            return Some((ech, ttl));
        }
        pos += rdlen;
    }
    None
}

/// Parse SVCB/HTTPS RDATA for the `ech` SvcParam (key 5). Only ServiceMode
/// records (SvcPriority >= 1) carry SvcParams; AliasMode (priority 0) has
/// just a TargetName and is skipped.
fn parse_svcb_ech_param(rdata: &[u8]) -> Option<Vec<u8>> {
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    if priority == 0 {
        return None; // AliasMode has no SvcParams
    }
    let mut pos = skip_name(rdata, 2).ok()?;
    while pos + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rdata.len() {
            return None;
        }
        if key == SVCB_KEY_ECH {
            return Some(rdata[pos..pos + len].to_vec());
        }
        pos += len;
    }
    None
}

/// Build a minimal DNS query (RD set, single question).
fn build_query(host: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&[0xda, 0xed]); // id
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&[0; 6]); // an/ns/ar = 0
    for label in host.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

/// Extract A/AAAA answer addresses from a DNS response.
fn parse_answers(msg: &[u8], qtype: u16) -> io::Result<Vec<IpAddr>> {
    if msg.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short DNS message",
        ));
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(msg, pos)?;
        pos = pos.checked_add(4).ok_or_else(bad)?; // qtype + qclass
    }
    let mut ips = Vec::new();
    for _ in 0..an {
        pos = skip_name(msg, pos)?;
        if pos + 10 > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated answer",
            ));
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated rdata",
            ));
        }
        if rtype == qtype {
            match (rtype, rdlen) {
                (1, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(
                    msg[pos],
                    msg[pos + 1],
                    msg[pos + 2],
                    msg[pos + 3],
                ))),
                (28, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&msg[pos..pos + 16]);
                    ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        pos += rdlen;
    }
    Ok(ips)
}

fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "bad DNS message")
}

/// Skip a (possibly compressed) domain name, returning the offset after it.
fn skip_name(msg: &[u8], mut pos: usize) -> io::Result<usize> {
    loop {
        let Some(&len) = msg.get(pos) else {
            return Err(bad());
        };
        if len & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        if len == 0 {
            return Ok(pos + 1);
        }
        pos += 1 + len as usize;
        if pos > msg.len() {
            return Err(bad());
        }
    }
}

#[cfg(test)]
pub(crate) static GLOBAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolver() {
        let r = BootstrapResolver::parse("udp://8.8.8.8:53").unwrap();
        assert_eq!(r.server, "8.8.8.8:53".parse().unwrap());
        assert!(!r.use_tcp);
        let r = BootstrapResolver::parse("tcp://1.1.1.1:53").unwrap();
        assert!(r.use_tcp);
        let r = BootstrapResolver::parse("9.9.9.9:53").unwrap();
        assert!(!r.use_tcp);
        assert!(BootstrapResolver::parse("").is_none());
        assert!(BootstrapResolver::parse("not-an-addr").is_none());
    }

    #[test]
    fn test_build_and_parse_roundtrip() {
        let query = build_query("example.com", 1);
        let mut resp = query.clone();
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[6] = 0;
        resp[7] = 1; // ancount = 1
        resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer
        resp.extend_from_slice(&1u16.to_be_bytes()); // A
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        resp.extend_from_slice(&[93, 184, 216, 34]);
        let ips = parse_answers(&resp, 1).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }

    #[tokio::test]
    async fn test_resolve_literal_ip_skips_lookup() {
        let ips = resolve("1.2.3.4").await.unwrap();
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    /// End-to-end: a stub UDP DNS server on loopback answering A records,
    /// installed as the global bootstrap resolver.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_resolve_via_bootstrap_udp() {
        let _lock = GLOBAL_TEST_LOCK.lock().unwrap();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..n].to_vec();
            resp[2] = 0x81;
            resp[3] = 0x80;
            resp[6] = 0;
            resp[7] = 1;
            resp.extend_from_slice(&[0xC0, 0x0C]);
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&60u32.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&[10, 9, 8, 7]);
            server.send_to(&resp, peer).await.unwrap();
        });

        set_global(BootstrapResolver::parse(&format!("udp://{}", server_addr)));
        let ips = resolve("node.example.com").await.unwrap();
        set_global(None);
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7))]);
    }

    /// Build a DNS response carrying one HTTPS (65) answer for the query's
    /// question, with the given priority and `ech` SvcParam (or none).
    fn make_https_response(query: &[u8], priority: u16, ech: Option<&[u8]>, ttl: u32) -> Vec<u8> {
        let mut resp = query.to_vec();
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[6] = 0;
        resp[7] = 1; // ancount = 1
        resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer to question
        resp.extend_from_slice(&65u16.to_be_bytes()); // TYPE HTTPS
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&ttl.to_be_bytes());
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.push(0); // target name = root
        if let Some(ech) = ech {
            rdata.extend_from_slice(&5u16.to_be_bytes()); // SvcParam key ech
            rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
            rdata.extend_from_slice(ech);
        }
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
        resp
    }

    #[test]
    fn test_parse_https_rr_ech() {
        let query = build_query("example.com", 65);
        let ech = b"\x00\x01fake-ech-config";
        // ServiceMode (priority >= 1) with an ech param.
        let resp = make_https_response(&query, 1, Some(ech), 300);
        assert_eq!(
            parse_https_rr_ech(&resp),
            Some((ech.to_vec(), 300)),
            "ServiceMode HTTPS RR with ech param"
        );

        // AliasMode (priority 0) carries no SvcParams — skipped even when
        // bytes shaped like params follow (they are part of the TargetName).
        let resp = make_https_response(&query, 0, Some(ech), 300);
        assert_eq!(parse_https_rr_ech(&resp), None);

        // ServiceMode without an ech param.
        let resp = make_https_response(&query, 1, None, 300);
        assert_eq!(parse_https_rr_ech(&resp), None);
    }

    /// End-to-end: stub UDP DNS server answering HTTPS records with an ech
    /// SvcParam, installed as the global bootstrap resolver.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_query_ech_config_via_bootstrap_udp() {
        let _lock = GLOBAL_TEST_LOCK.lock().unwrap();
        let ech = b"\x00\x02real-ech-bytes";
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let resp = make_https_response(&buf[..n], 1, Some(ech), 120);
            server.send_to(&resp, peer).await.unwrap();
        });

        set_global(BootstrapResolver::parse(&format!("udp://{}", server_addr)));
        let got = query_ech_config("node.example.com").await.unwrap();
        set_global(None);
        assert_eq!(got, Some((ech.to_vec(), 120)));

        // IP literals never hit the network.
        assert_eq!(query_ech_config("1.2.3.4").await.unwrap(), None);
    }
}
