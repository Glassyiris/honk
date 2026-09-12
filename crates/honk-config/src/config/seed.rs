use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::Config;
use crate::config::diagnostics::ineffective_group_option_diagnostic;
use crate::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SettingPath, SourceRef, report_detailed_diagnostics,
};
use crate::node::{Node, RawNodeSeed};

pub(crate) const CONFIG_FIELDS: &[&str] = &[
    "global",
    "dns",
    "routing",
    "nodes",
    "groups",
    "subscriptions",
    "experimental",
];

/// Public data-only adapter. Its serde errors are always redacted.
pub struct ConfigSeed<'a> {
    pub diagnostics: &'a mut Vec<DetailedDiagnostic>,
    pub source: SourceRef,
}

/// Internal adapter used by format-specific loaders before they project errors.
pub(super) struct RawConfigSeed<'a> {
    pub(super) diagnostics: &'a mut Vec<DetailedDiagnostic>,
    pub(super) source: SourceRef,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum Field {
    Global,
    Dns,
    Routing,
    Nodes,
    Groups,
    Subscriptions,
    Experimental,
    #[serde(other)]
    Ignore,
}

impl<'de> DeserializeSeed<'de> for ConfigSeed<'_> {
    type Value = Config;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Config, D::Error> {
        RawConfigSeed {
            diagnostics: self.diagnostics,
            source: self.source,
        }
        .deserialize(deserializer)
        .map_err(|_| D::Error::custom("invalid configuration fields"))
    }
}

impl<'de> DeserializeSeed<'de> for RawConfigSeed<'_> {
    type Value = Config;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Config, D::Error> {
        deserializer.deserialize_struct("Config", CONFIG_FIELDS, self)
    }
}

impl<'de> Visitor<'de> for RawConfigSeed<'_> {
    type Value = Config;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a configuration")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Config, A::Error> {
        let mut config = Config::default();
        let mut seen = 0u8;
        while let Some(field) = map.next_key::<Field>()? {
            if matches!(field, Field::Ignore) {
                map.next_value::<serde::de::IgnoredAny>()?;
                continue;
            }
            let bit = 1 << field as u8;
            if seen & bit != 0 {
                return Err(A::Error::custom("duplicate configuration field"));
            }
            seen |= bit;
            match field {
                Field::Global => config.global = map.next_value()?,
                Field::Dns => config.dns = map.next_value()?,
                Field::Routing => config.routing = map.next_value()?,
                Field::Nodes => {
                    config.nodes = map.next_value_seed(RawNodesSeed {
                        diagnostics: self.diagnostics,
                        source: self.source.clone(),
                    })?
                }
                Field::Groups => {
                    config.groups = map.next_value()?;
                    for (index, group) in config.groups.iter().enumerate() {
                        if group.interrupt_connections {
                            self.diagnostics.push(ineffective_group_option_diagnostic(
                                self.source.clone(),
                                index + 1,
                            ));
                        }
                    }
                }
                Field::Subscriptions => config.subscriptions = map.next_value()?,
                Field::Experimental => {
                    config.experimental = map.next_value()?;
                    if config.experimental.legacy_udp_nfqueue.is_some() {
                        self.diagnostics
                            .push(crate::diagnostic::legacy_nfqueue_warning(
                                self.source.clone(),
                            ));
                    }
                    if let Some(diagnostic) = config
                        .experimental
                        .clash_api
                        .exposure_diagnostic(self.source.clone())
                    {
                        self.diagnostics.push(diagnostic);
                    }
                }
                Field::Ignore => unreachable!(),
            }
        }
        Ok(config)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Config, A::Error> {
        // Derived Config serde also accepts sequences in declaration order.
        let global = seq.next_element()?.unwrap_or_default();
        let dns = seq.next_element()?.unwrap_or_default();
        let routing = seq.next_element()?.unwrap_or_default();
        let nodes = seq
            .next_element_seed(RawNodesSeed {
                diagnostics: self.diagnostics,
                source: self.source.clone(),
            })?
            .unwrap_or_default();
        let groups: Vec<crate::node::Group> = seq.next_element()?.unwrap_or_default();
        for (index, group) in groups.iter().enumerate() {
            if group.interrupt_connections {
                self.diagnostics.push(ineffective_group_option_diagnostic(
                    self.source.clone(),
                    index + 1,
                ));
            }
        }
        let subscriptions = seq.next_element()?.unwrap_or_default();
        let experimental: crate::experimental::ExperimentalConfig =
            seq.next_element()?.unwrap_or_default();
        if experimental.legacy_udp_nfqueue.is_some() {
            self.diagnostics
                .push(crate::diagnostic::legacy_nfqueue_warning(
                    self.source.clone(),
                ));
        }
        if let Some(diagnostic) = experimental
            .clash_api
            .exposure_diagnostic(self.source.clone())
        {
            self.diagnostics.push(diagnostic);
        }
        Ok(Config {
            global,
            dns,
            routing,
            nodes,
            groups,
            subscriptions,
            experimental,
        })
    }
}

struct RawNodesSeed<'a> {
    diagnostics: &'a mut Vec<DetailedDiagnostic>,
    source: SourceRef,
}
impl<'de> DeserializeSeed<'de> for RawNodesSeed<'_> {
    type Value = Vec<Node>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for RawNodesSeed<'_> {
    type Value = Vec<Node>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a node sequence")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut nodes = Vec::new();
        while let Some(node) = seq.next_element_seed(RawNodeSeed {
            diagnostics: self.diagnostics,
            source: self.source.clone(),
            setting: SettingPath::new("nodes").index(nodes.len() + 1),
            record_semantic: true,
        })? {
            nodes.push(node);
        }
        Ok(nodes)
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut diagnostics = Vec::new();
        let result = ConfigSeed {
            diagnostics: &mut diagnostics,
            source: DiagnosticSources::new(None).root(),
        }
        .deserialize(deserializer);
        report_detailed_diagnostics(&diagnostics);
        result
    }
}
