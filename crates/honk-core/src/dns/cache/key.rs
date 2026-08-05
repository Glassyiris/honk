use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::dns::planner::RequestScope;
use crate::dns::policy::PolicyId;
use crate::dns::query::{IngressProfile, QueryContext};

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

    pub(crate) const fn shard_hash(&self) -> u64 {
        self.shard_hash
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
    Sha256::digest(key.as_bytes()).into()
}
