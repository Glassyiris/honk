use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::dns::planner::RequestScope;
use crate::dns::policy::PolicyId;
use crate::dns::query::{IngressProfile, QueryContext};

const MAGIC: &[u8; 4] = b"HDCK";
const VERSION: u8 = 1;
const STORAGE_PREFIX: &str = "honk-dns-cache-key:v1:";
const DIGEST_HEX_LEN: usize = 64;

const FIELD_WIRE: u8 = 0x01;
const FIELD_INGRESS: u8 = 0x02;
const FIELD_POLICY: u8 = 0x03;
const FIELD_SCOPE: u8 = 0x04;
const FIELD_OPERATION: u8 = 0x05;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OperationKind {
    Resolve,
    Refresh,
}

/// Immutable query identity shared by all cache and singleflight operations for
/// one prepared DNS query.  The canonical wire form is deliberately retained
/// as bytes; its textual representation is a persistence boundary only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct KeyIdentity(Arc<KeyIdentityData>);

#[derive(Debug, PartialEq, Eq, Hash)]
struct KeyIdentityData {
    wire_identity: Arc<[u8]>,
    ingress: IngressProfile,
    policy_id: Option<PolicyId>,
}

impl KeyIdentity {
    pub(crate) fn new(query: &QueryContext, policy_id: Option<PolicyId>) -> Self {
        Self(Arc::new(KeyIdentityData {
            wire_identity: query.canonical_wire_arc(),
            ingress: query.ingress(),
            policy_id,
        }))
    }

    pub(crate) fn key(&self, scope: RequestScope, operation: OperationKind) -> CacheKey {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        scope.hash(&mut hasher);
        operation.hash(&mut hasher);
        CacheKey {
            identity: self.clone(),
            scope,
            operation,
            shard_hash: hasher.finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    identity: KeyIdentity,
    scope: RequestScope,
    operation: OperationKind,
    shard_hash: u64,
}

impl CacheKey {
    pub(crate) fn new(
        query: &QueryContext,
        policy_id: Option<PolicyId>,
        scope: RequestScope,
        operation: OperationKind,
    ) -> Self {
        KeyIdentity::new(query, policy_id).key(scope, operation)
    }

    /// Change only the operation discriminator while preserving the canonical
    /// query identity and request scope.
    pub(crate) fn with_operation(&self, operation: OperationKind) -> Self {
        self.identity.key(self.scope.clone(), operation)
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.identity.0.wire_identity.len() + 96);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(FIELD_WIRE);
        put_bytes(&mut bytes, &self.identity.0.wire_identity);
        encode_ingress(&mut bytes, self.identity.0.ingress);
        encode_policy(&mut bytes, self.identity.0.policy_id.as_ref());
        encode_scope(&mut bytes, &self.scope);
        bytes.extend_from_slice(&[
            FIELD_OPERATION,
            match self.operation {
                OperationKind::Resolve => 0x40,
                OperationKind::Refresh => 0x41,
            },
        ]);
        bytes
    }
    pub(crate) const fn shard_hash(&self) -> u64 {
        self.shard_hash
    }

    /// SQLite and legacy callers use this stable, human-safe encoding. Runtime
    /// cache paths should use the binary `CacheKey` directly.
    pub(crate) fn storage_key(&self) -> String {
        let canonical = self.canonical_bytes();
        format!(
            "{STORAGE_PREFIX}{}:{}",
            hex(&Sha256::digest(&canonical)),
            hex(&canonical)
        )
    }

    pub(crate) const fn operation(&self) -> OperationKind {
        self.operation
    }

    pub(crate) fn wire_identity(&self) -> &[u8] {
        &self.identity.0.wire_identity
    }

    pub(crate) fn ingress(&self) -> IngressProfile {
        self.identity.0.ingress
    }

    pub(crate) fn policy_id(&self) -> Option<&PolicyId> {
        self.identity.0.policy_id.as_ref()
    }

    pub(crate) const fn scope(&self) -> &RequestScope {
        &self.scope
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        wire_identity: Vec<u8>,
        ingress: IngressProfile,
        scope: RequestScope,
        operation: OperationKind,
    ) -> Self {
        KeyIdentity(Arc::new(KeyIdentityData {
            wire_identity: wire_identity.into(),
            ingress,
            policy_id: None,
        }))
        .key(scope, operation)
    }
}

pub(super) fn stable_shard_digest(key: &str) -> [u8; 32] {
    let digest = key
        .strip_prefix(STORAGE_PREFIX)
        .filter(|suffix| suffix.get(DIGEST_HEX_LEN..DIGEST_HEX_LEN + 1) == Some(":"))
        .and_then(|suffix| suffix.get(..DIGEST_HEX_LEN))
        .and_then(decode_digest);
    digest.unwrap_or_else(|| Sha256::digest(key.as_bytes()).into())
}

fn encode_ingress(bytes: &mut Vec<u8>, ingress: IngressProfile) {
    bytes.push(FIELD_INGRESS);
    match ingress {
        IngressProfile::Udp { advertised_size } => {
            bytes.push(0x10);
            bytes.extend_from_slice(&advertised_size.to_be_bytes());
        }
        IngressProfile::Tcp => bytes.push(0x11),
        IngressProfile::Api => bytes.push(0x12),
        IngressProfile::Internal => bytes.push(0x13),
    }
}

fn encode_policy(bytes: &mut Vec<u8>, policy: Option<&PolicyId>) {
    bytes.push(FIELD_POLICY);
    match policy {
        None => bytes.push(0x20),
        Some(policy) => {
            bytes.push(0x21);
            bytes.extend_from_slice(policy.digest());
            put_bytes(bytes, policy.canonical_bytes());
        }
    }
}

fn encode_scope(bytes: &mut Vec<u8>, scope: &RequestScope) {
    bytes.push(FIELD_SCOPE);
    match scope {
        RequestScope::Upstream(tag) => {
            bytes.push(0x30);
            put_bytes(bytes, tag.as_str().as_bytes());
        }
        RequestScope::AsIs(address) => {
            bytes.push(0x31);
            match address.ip() {
                IpAddr::V4(ip) => {
                    bytes.push(0x32);
                    bytes.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    bytes.push(0x33);
                    bytes.extend_from_slice(&ip.octets());
                }
            }
            bytes.extend_from_slice(&address.port().to_be_bytes());
        }
    }
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        },
    )
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != DIGEST_HEX_LEN {
        return None;
    }
    let mut digest = [0; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        let start = index * 2;
        let pair = value.get(start..start + 2)?;
        *output = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(digest)
}
