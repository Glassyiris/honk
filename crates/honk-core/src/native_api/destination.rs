//! The administrator's outbound destination policy for geodata downloads.

use std::{net::IpAddr, sync::LazyLock};

use honk_config::experimental::NativeApiConfig;
use ipnet::IpNet;

/// Special-purpose ranges refused unless `probe_allowed_cidrs` names them.
static RESTRICTED: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
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
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
    ]
    .iter()
    .map(|value| value.parse().expect("static CIDR"))
    .collect()
});

/// Default ports and public addresses unless `probe_allowed_ports` and
/// `probe_allowed_cidrs` widen it.
pub(crate) struct Policy {
    allowed: Vec<IpNet>,
    ports: Vec<u16>,
}

impl Policy {
    pub(crate) fn new(config: &NativeApiConfig) -> Self {
        Self {
            allowed: config
                .probe_allowed_cidrs
                .iter()
                .map(|value| value.parse().expect("validated probe CIDR"))
                .collect(),
            ports: config.probe_allowed_ports.clone(),
        }
    }

    pub(crate) fn address(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        let restricted = RESTRICTED.iter().any(|net| net.contains(&ip))
            || match ip {
                IpAddr::V4(_) => false,
                IpAddr::V6(ip) => ip.segments()[0] & 0xe000 != 0x2000,
            };
        !restricted || self.allowed.iter().any(|net| net.contains(&ip))
    }

    pub(crate) fn http_port(&self, port: u16, https: bool) -> bool {
        port != 0 && (port == if https { 443 } else { 80 } || self.ports.contains(&port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_addresses_require_cidr_even_with_allowed_ports() {
        let mut config = NativeApiConfig {
            probe_allowed_ports: vec![8080],
            ..Default::default()
        };
        let policy = Policy::new(&config);
        assert!(!policy.address("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!policy.address("169.254.169.254".parse().unwrap()));
        assert!(policy.http_port(8080, false));
        assert!(!policy.http_port(443, false));
        config.probe_allowed_cidrs = vec!["127.0.0.0/8".into()];
        assert!(Policy::new(&config).address("::ffff:127.0.0.1".parse().unwrap()));
    }
}
