mod canonical;

use std::fmt;
use std::sync::Arc;

use honk_config::dns::DnsConfig;
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PolicyId {
    digest: [u8; 32],
    canonical: Arc<[u8]>,
}

impl PolicyId {
    pub fn from_config(config: &DnsConfig) -> Result<Self, PolicyError> {
        let canonical = canonical::encode(config)?;
        let digest = Sha256::digest(&canonical).into();
        Ok(Self {
            digest,
            canonical: canonical.into(),
        })
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub fn digest_hex(&self) -> String {
        format!("{self}")
    }
}

impl fmt::Debug for PolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PolicyId")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.digest {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("DNS upstream '{upstream}' has an invalid endpoint: {source}")]
    InvalidEndpoint {
        upstream: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("DNS policy contains an empty {field}")]
    EmptyName { field: &'static str },
    #[error("DNS policy contains invalid endpoint host '{value}'")]
    InvalidHost { value: String },
    #[error("DNS policy contains invalid CIDR '{value}'")]
    InvalidCidr { value: String },
    #[error("DNS policy contains invalid regex '{value}': {source}")]
    InvalidRegex {
        value: String,
        #[source]
        source: regex::Error,
    },
    #[error("DNS canonical field is too large to encode")]
    FieldTooLarge,
}

#[cfg(test)]
mod normalization_tests;
#[cfg(test)]
mod tests;
