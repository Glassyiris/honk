use serde::{Deserialize, Serialize};

/// A routing rule that matches traffic and sends it to an outbound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Display name
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
}

impl RoutingCondition {
    /// Render the condition back to a dae-style rule expression, e.g.
    /// `domain(suffix: google.com) && dip(geoip: cn)` — display-only
    /// (clash `/connections` rule field, logs); not a parse round-trip.
    pub fn display_expr(&self) -> String {
        fn fn_call(name: &str, args: &[String]) -> Option<String> {
            if args.is_empty() {
                None
            } else {
                Some(format!("{}({})", name, args.join(", ")))
            }
        }
        let mut parts: Vec<String> = Vec::new();
        // All domain-family matchers are one `domain(...)` call (OR within).
        let mut domain_args: Vec<String> = Vec::new();
        for v in &self.domain {
            domain_args.push(format!("full: {v}"));
        }
        for v in &self.domain_suffix {
            domain_args.push(format!("suffix: {v}"));
        }
        for v in &self.domain_keyword {
            domain_args.push(format!("keyword: {v}"));
        }
        for v in &self.domain_regex {
            domain_args.push(format!("regex: {v}"));
        }
        for v in &self.geosite {
            domain_args.push(format!("geosite: {v}"));
        }
        if let Some(e) = fn_call("domain", &domain_args) {
            parts.push(e);
        }
        // ip and geo_ip both come from `dip(...)` — keep them in one call
        // (splitting into two &&-ed calls would change OR into AND).
        let mut dip_args = self.ip.clone();
        dip_args.extend(self.geo_ip.iter().map(|c| format!("geoip: {c}")));
        if let Some(e) = fn_call("dip", &dip_args) {
            parts.push(e);
        }
        if let Some(e) = fn_call("sip", &self.source_ip) {
            parts.push(e);
        }
        if let Some(e) = fn_call("dport", &self.port) {
            parts.push(e);
        }
        if let Some(e) = fn_call("sport", &self.source_port) {
            parts.push(e);
        }
        if let Some(e) = fn_call("l4proto", &self.protocol) {
            parts.push(e);
        }
        if let Some(e) = fn_call("pname", &self.process_name) {
            parts.push(e);
        }
        if let Some(e) = fn_call("mac", &self.mac) {
            parts.push(e);
        }
        if let Some(e) = fn_call("ipversion", &self.ip_version) {
            parts.push(e);
        }
        if let Some(e) = fn_call("dscp", &self.dscp) {
            parts.push(e);
        }
        parts.join(" && ")
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
