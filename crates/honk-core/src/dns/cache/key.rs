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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyIdentity(Arc<KeyIdentityData>);

#[derive(Debug, PartialEq, Eq)]
struct KeyIdentityData {
    wire_identity: Arc<[u8]>,
    ingress: IngressProfile,
    policy_id: Option<PolicyId>,
    identity_hash: u64,
}

impl Hash for KeyIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.0.identity_hash);
    }
}

fn hash_identity(
    wire_identity: &[u8],
    ingress: IngressProfile,
    policy_id: &Option<PolicyId>,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    wire_identity.hash(&mut hasher);
    ingress.hash(&mut hasher);
    policy_id.hash(&mut hasher);
    hasher.finish()
}

impl KeyIdentity {
    pub(crate) fn new(query: &QueryContext, policy_id: Option<PolicyId>) -> Self {
        let wire_identity = query.canonical_wire_arc();
        let ingress = query.ingress();
        let identity_hash = hash_identity(wire_identity.as_ref(), ingress, &policy_id);
        Self(Arc::new(KeyIdentityData {
            wire_identity,
            ingress,
            policy_id,
            identity_hash,
        }))
    }

    pub(crate) fn key(&self, scope: RequestScope, operation: OperationKind) -> CacheKey {
        // ponytail: one query's bounded scope/operation variants share a shard;
        // mix them only if collision profiling shows contention.
        CacheKey {
            identity: self.clone(),
            scope,
            operation,
            shard_hash: self.0.identity_hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CacheKey {
    identity: KeyIdentity,
    scope: RequestScope,
    operation: OperationKind,
    shard_hash: u64,
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.shard_hash);
    }
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
        let wire_identity = Arc::<[u8]>::from(wire_identity);
        let policy_id = None;
        let identity_hash = hash_identity(wire_identity.as_ref(), ingress, &policy_id);
        KeyIdentity(Arc::new(KeyIdentityData {
            wire_identity,
            ingress,
            policy_id,
            identity_hash,
        }))
        .key(scope, operation)
    }
}

pub(super) fn stable_shard_digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}
