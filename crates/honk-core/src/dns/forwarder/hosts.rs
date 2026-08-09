//! Immutable `/etc/hosts` snapshots for one DNS runtime generation.
//!
//! Loading happens while a generation is built, so SIGHUP publishes hosts,
//! policy, transports, and routing together. Query handling performs no file I/O.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::Path;

use crate::dns::engine::{DnsEngine, ParsedQuery};
use crate::dns::outcome::DnsOutcome;

use super::response::make_address_response;
use super::{DnsForwardError, DnsForwarder, ResolveMode};

pub(super) const SYSTEM_HOSTS_PATH: &str = "/etc/hosts";
const HOSTS_TTL_SECS: u32 = 60;

#[derive(Debug, Default)]
pub(super) struct HostsFile {
    entries: HashMap<String, Vec<IpAddr>>,
}

impl HostsFile {
    pub(super) fn load(path: &Path) -> io::Result<Self> {
        fs::read_to_string(path).map(|contents| Self::parse(&contents))
    }

    fn parse(contents: &str) -> Self {
        let mut entries: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for line in contents.lines() {
            let fields = line
                .split_once('#')
                .map_or(line, |(record, _)| record)
                .split_whitespace();
            let mut fields = fields;
            let Some(address) = fields.next().and_then(|value| value.parse::<IpAddr>().ok()) else {
                continue;
            };
            for hostname in fields {
                let hostname = normalize_hostname(hostname);
                if hostname.is_empty() {
                    continue;
                }
                let addresses = entries.entry(hostname).or_default();
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        Self { entries }
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn address_count(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    fn response(&self, raw_query: &[u8], parsed: &ParsedQuery) -> Option<Vec<u8>> {
        if parsed.query().qclass()?.get() != 1 || !matches!(parsed.qtype(), 1 | 28) {
            return None;
        }
        let addresses = self.entries.get(parsed.domain())?;
        Some(make_address_response(
            raw_query,
            parsed.query(),
            addresses,
            HOSTS_TTL_SECS,
        ))
    }
}

fn normalize_hostname(hostname: &str) -> String {
    let mut hostname = hostname.trim_end_matches('.').to_owned();
    hostname.make_ascii_lowercase();
    hostname
}

impl DnsForwarder {
    pub(crate) fn resolve_hosts(
        &self,
        engine: &DnsEngine,
        parsed: &ParsedQuery,
        raw_query: &[u8],
        mode: ResolveMode,
    ) -> Result<Option<DnsOutcome>, DnsForwardError> {
        let Some(response) = self
            .hosts
            .as_deref()
            .and_then(|hosts| hosts.response(raw_query, parsed))
        else {
            return Ok(None);
        };
        self.local_outcome_from_wire(engine, parsed, response, mode)
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use honk_config::dns::{
        DnsCond, DnsConfig, DnsDomainMatcher, DnsRequestAction, DnsRequestRule,
    };
    use tempfile::{NamedTempFile, tempdir};
    use tokio::sync::Mutex;

    use crate::dns::cache::DnsCache;
    use crate::dns::forwarder::{DnsUpstreamPool, build_dns_query};
    use crate::dns::outcome::{OutcomeStatus, Provenance, ResponseClass};
    use crate::dns::query::QueryContext;
    use crate::dns::routing::DnsRouter;

    use super::super::response::make_empty_response;
    use super::*;

    #[derive(Default)]
    struct CountingUpstream {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DnsUpstreamPool for CountingUpstream {
        async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let query = QueryContext::parse(raw_query)?;
            Ok(make_empty_response(raw_query, &query))
        }
    }

    fn hosts_file(contents: &str) -> NamedTempFile {
        let file = NamedTempFile::new().expect("temporary hosts file");
        std::fs::write(file.path(), contents).expect("write hosts file");
        file
    }

    fn test_forwarder(
        path: &Path,
        config: &DnsConfig,
        upstream: Arc<CountingUpstream>,
    ) -> DnsForwarder {
        let router = Arc::new(DnsRouter::new_from_dns_config(config).expect("DNS router"));
        let upstream: Arc<dyn DnsUpstreamPool> = upstream;
        DnsForwarder::new(upstream, Arc::new(Mutex::new(DnsCache::new(100))), router)
            .with_policy_from_config(config)
            .expect("DNS policy")
            .with_hosts_file(config.use_host, path)
            .expect("hosts snapshot")
    }

    #[test]
    fn parser_normalizes_aliases_and_deduplicates_addresses() {
        let hosts = HostsFile::parse(
            "127.0.0.1 LOCALHOST localhost. alias # inline comment\n\
             ::1 localhost\n\
             invalid ignored\n\
             192.0.2.1 alias alias\n",
        );

        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts.address_count(), 4);
        assert_eq!(
            hosts.entries.get("localhost"),
            Some(&vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ])
        );
        assert_eq!(
            hosts.entries.get("alias"),
            Some(&vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ])
        );
    }

    #[tokio::test]
    async fn hosts_answers_a_and_aaaa_before_request_reject() {
        let file = hosts_file("192.0.2.10 service.test\n2001:db8::10 service.test\n");
        let upstream = Arc::new(CountingUpstream::default());
        let mut config = DnsConfig {
            use_host: true,
            ..Default::default()
        };
        config.routing.request.rules = vec![DnsRequestRule {
            conditions: vec![DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Full("service.test".into())],
            }],
            action: DnsRequestAction::Reject,
        }];
        let forwarder = test_forwarder(file.path(), &config, Arc::clone(&upstream));

        let mut a_query = build_dns_query("SERVICE.TEST", 1);
        a_query[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        let a = forwarder
            .resolve_outcome(&a_query)
            .await
            .expect("A outcome");
        let aaaa = forwarder
            .resolve_outcome(&build_dns_query("service.test", 28))
            .await
            .expect("AAAA outcome");

        assert_eq!(a.status(), OutcomeStatus::Accepted);
        assert_eq!(a.provenance(), Provenance::Fresh);
        assert_eq!(a.response_class(), ResponseClass::Positive);
        assert!(!a.expiry().is_cacheable());
        assert_eq!(&a.rendered()[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(a.answer_ips(), &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        assert_eq!(
            aaaa.answer_ips(),
            &[IpAddr::V6("2001:db8::10".parse().unwrap())]
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn known_name_family_miss_is_nodata_but_other_queries_use_upstream() {
        let file = hosts_file("192.0.2.20 ipv4-only.test\n");
        let upstream = Arc::new(CountingUpstream::default());
        let config = DnsConfig {
            use_host: true,
            ..Default::default()
        };
        let forwarder = test_forwarder(file.path(), &config, Arc::clone(&upstream));

        let family_miss = forwarder
            .resolve_outcome(&build_dns_query("ipv4-only.test", 28))
            .await
            .expect("AAAA outcome");
        assert_eq!(family_miss.status(), OutcomeStatus::Accepted);
        assert_eq!(family_miss.response_class(), ResponseClass::Nodata);
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);

        forwarder
            .resolve_outcome(&build_dns_query("ipv4-only.test", 16))
            .await
            .expect("TXT outcome");
        forwarder
            .resolve_outcome(&build_dns_query("unknown.test", 1))
            .await
            .expect("unknown A outcome");
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rebuilt_forwarder_loads_a_new_snapshot_without_mutating_the_old_one() {
        let file = hosts_file("192.0.2.30 reload.test\n");
        let upstream = Arc::new(CountingUpstream::default());
        let config = DnsConfig {
            use_host: true,
            ..Default::default()
        };
        let old = test_forwarder(file.path(), &config, Arc::clone(&upstream));

        std::fs::write(file.path(), "192.0.2.31 reload.test\n").expect("replace hosts file");
        let new = test_forwarder(file.path(), &config, Arc::clone(&upstream));

        let query = build_dns_query("reload.test", 1);
        let old_outcome = old.resolve_outcome(&query).await.expect("old snapshot");
        let new_outcome = new.resolve_outcome(&query).await.expect("new snapshot");
        assert_eq!(
            old_outcome.answer_ips(),
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30))]
        );
        assert_eq!(
            new_outcome.answer_ips(),
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31))]
        );
        assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn enabled_hosts_load_failure_is_fatal_but_disabled_hosts_skips_io() {
        let directory = tempdir().expect("temporary directory");
        let missing = directory.path().join("missing-hosts");
        let config = DnsConfig::default();
        let router = Arc::new(DnsRouter::new_from_dns_config(&config).expect("DNS router"));
        let upstream: Arc<dyn DnsUpstreamPool> = Arc::new(CountingUpstream::default());
        let forwarder =
            DnsForwarder::new(upstream, Arc::new(Mutex::new(DnsCache::new(100))), router);

        assert!(forwarder.clone().with_hosts_file(false, &missing).is_ok());
        assert!(forwarder.with_hosts_file(true, &missing).is_err());
    }
}
