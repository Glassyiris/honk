//! Engine-side observation contract: identities and evidence the data path
//! records, independent of the native HTTP surface that serves them.

pub(crate) mod catalog;
pub(crate) mod rules;

use std::time::SystemTime;

pub(crate) fn timestamp(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
