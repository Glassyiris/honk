//! Engine-side observation contract: identities and evidence the data path
//! records, independent of the native HTTP surface that serves them.

pub(crate) mod catalog;
mod dns;
pub(crate) mod flows;
pub(crate) mod rules;

pub(crate) use dns::{DnsLog, DnsRecorder};

use std::time::SystemTime;

use serde_json::Value;

/// Where recorded evidence announces itself to readers.
pub(crate) trait Events: Send + Sync {
    fn publish(&self, kind: &'static str, data: Value, flow_id: Option<&str>);
    fn flow_updated(&self, flow_id: &str, revision: u64);
}

pub(crate) fn timestamp(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
