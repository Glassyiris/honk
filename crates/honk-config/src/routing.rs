use serde::{Deserialize, Serialize};

/// A routing rule that matches traffic and sends it to an outbound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    #[serde(default)]
    pub name: String,
    /// Match conditions
    #[serde(flatten)]
    pub condition: RoutingCondition,
    /// Outbound target
    pub outbound: RoutingOutbound,
    /// Priority (lower = higher priority)
    #[serde(default)]
    pub priority: u32,
    /// If true, this is a "must" rule: matching it does NOT produce a final
    /// outbound decision. Instead, the search continues and the must flag is
    /// propagated to the next matching rule's outbound (Go dae compatible).
    #[serde(default)]
    pub must: bool,
    /// fwmark to set on matched connections (0 = no mark).
    #[serde(default)]
    pub mark: u32,
}

/// Conditions for matching traffic.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingCondition {
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub domain_regex: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub source_ip: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>,
    #[serde(default)]
    pub source_port: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub process_name: Vec<String>,
    #[serde(default)]
    pub mac: Vec<String>,
    #[serde(default)]
    pub geo_ip: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub ip_version: Vec<String>,
    #[serde(default)]
    pub dscp: Vec<String>,
    /// Negated matchers (dae `!matcher(...)`): a rule matches iff every
    /// positive matcher matches and none of these do.
    #[serde(default)]
    pub not: RoutingNotCondition,
}

/// Negated matcher set of a routing rule, mirroring [`RoutingCondition`]
/// field for field. Kept as a separate struct so existing serde configs
/// without a `not` key keep parsing unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingNotCondition {
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub domain_regex: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub source_ip: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>,
    #[serde(default)]
    pub source_port: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub process_name: Vec<String>,
    #[serde(default)]
    pub mac: Vec<String>,
    #[serde(default)]
    pub geo_ip: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub ip_version: Vec<String>,
    #[serde(default)]
    pub dscp: Vec<String>,
}

/// Mutable view over one matcher field set. The dae parser dispatches each
/// `&&` part into either the positive or the negated set through this view.
pub(crate) struct ConditionFields<'a> {
    pub domain: &'a mut Vec<String>,
    pub domain_suffix: &'a mut Vec<String>,
    pub domain_keyword: &'a mut Vec<String>,
    pub domain_regex: &'a mut Vec<String>,
    pub ip: &'a mut Vec<String>,
    pub source_ip: &'a mut Vec<String>,
    pub port: &'a mut Vec<String>,
    pub source_port: &'a mut Vec<String>,
    pub protocol: &'a mut Vec<String>,
    pub process_name: &'a mut Vec<String>,
    pub mac: &'a mut Vec<String>,
    pub geo_ip: &'a mut Vec<String>,
    pub geosite: &'a mut Vec<String>,
    pub ip_version: &'a mut Vec<String>,
    pub dscp: &'a mut Vec<String>,
}

macro_rules! fields_mut {
    ($self:ident) => {
        ConditionFields {
            domain: &mut $self.domain,
            domain_suffix: &mut $self.domain_suffix,
            domain_keyword: &mut $self.domain_keyword,
            domain_regex: &mut $self.domain_regex,
            ip: &mut $self.ip,
            source_ip: &mut $self.source_ip,
            port: &mut $self.port,
            source_port: &mut $self.source_port,
            protocol: &mut $self.protocol,
            process_name: &mut $self.process_name,
            mac: &mut $self.mac,
            geo_ip: &mut $self.geo_ip,
            geosite: &mut $self.geosite,
            ip_version: &mut $self.ip_version,
            dscp: &mut $self.dscp,
        }
    };
}

impl RoutingCondition {
    pub(crate) fn fields_mut(&mut self) -> ConditionFields<'_> {
        fields_mut!(self)
    }
}

impl RoutingNotCondition {
    pub(crate) fn fields_mut(&mut self) -> ConditionFields<'_> {
        fields_mut!(self)
    }
}

impl RoutingCondition {
    /// Clash-style `(rule, rulePayload)` pair for the matched rule: the
    /// rule's OWN type and payload (e.g. `("GeoIP", "telegram")`), NOT the
    /// connection's domain/IP — `/connections` `metadata.host` already
    /// carries that. First non-empty condition kind wins (declaration order
    /// below matches typical dae rule shape); multi-value payloads are
    /// comma-joined. Returns `None` for a condition-less rule (fallback
    /// renders as `Match`).
    pub fn clash_rule_parts(&self) -> Option<(&'static str, String)> {
        let pick = |ty: &'static str, vals: &[String]| {
            if vals.is_empty() {
                None
            } else {
                Some((ty, vals.join(",")))
            }
        };
        pick("domain", &self.domain)
            .or_else(|| pick("suffix", &self.domain_suffix))
            .or_else(|| pick("keyword", &self.domain_keyword))
            .or_else(|| pick("regex", &self.domain_regex))
            .or_else(|| pick("geosite", &self.geosite))
            .or_else(|| pick("dip", &self.ip))
            .or_else(|| pick("geoip", &self.geo_ip))
            .or_else(|| pick("src_ip", &self.source_ip))
            .or_else(|| pick("dport", &self.port))
            .or_else(|| pick("sport", &self.source_port))
            .or_else(|| pick("protocol", &self.protocol))
            .or_else(|| pick("process", &self.process_name))
            .or_else(|| pick("smac", &self.mac))
            .or_else(|| pick("ip_version", &self.ip_version))
            .or_else(|| pick("dscp", &self.dscp))
    }
}

/// Outbound target for routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RoutingOutbound {
    /// Simple outbound name
    Simple(String),
    /// Complex outbound with chain/balancer
    Complex {
        /// Outbound type
        #[serde(rename = "type")]
        outbound_type: RoutingOutboundType,
        /// Outbound names
        outbounds: Vec<String>,
    },
}

/// Outbound type for complex routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingOutboundType {
    /// Logical OR (try each in order)
    Or,
    /// Logical AND (all must succeed)
    And,
    /// Load balancer
    Balancer,
    /// Chain (one after another)
    Chain,
}

/// Routing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Routing rules
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    /// Default outbound when no rules match
    #[serde(default = "default_outbound")]
    pub default_outbound: String,
}

fn default_outbound() -> String {
    "direct".to_string()
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            rules: vec![],
            default_outbound: "direct".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clash_rule_parts_picks_first_condition_kind() {
        let cond = RoutingCondition {
            geosite: vec!["category-dev".into()],
            ..Default::default()
        };
        assert_eq!(
            cond.clash_rule_parts(),
            Some(("geosite", "category-dev".to_string()))
        );

        let cond = RoutingCondition {
            ip: vec!["1.0.0.0/8".into()],
            geo_ip: vec!["telegram".into()],
            ..Default::default()
        };
        assert_eq!(
            cond.clash_rule_parts(),
            Some(("dip", "1.0.0.0/8".to_string()))
        );

        let cond = RoutingCondition {
            port: vec!["22".into(), "80".into(), "443".into()],
            ..Default::default()
        };
        assert_eq!(
            cond.clash_rule_parts(),
            Some(("dport", "22,80,443".to_string()))
        );

        assert_eq!(RoutingCondition::default().clash_rule_parts(), None);
    }
}
