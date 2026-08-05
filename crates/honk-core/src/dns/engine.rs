use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;

use super::cache::KeyIdentity;
use super::outcome::ResponseClass;
use super::planner::{
    PlanError, Planner, RequestContext, RequestPlan, RequestScope, ResponseContext, ResponsePlan,
    ResponseTraversal, UpstreamTag,
};
use super::policy::PolicyId;
use super::query::{DnsName, IngressProfile, QueryContext, QueryError};
use super::response::{ResponseError, ResponseTemplate};
use super::routing::DnsRouter;

mod metadata;
pub(crate) mod pipeline;

pub(crate) use metadata::{classify_response, effective_expiry};

pub(crate) struct DnsEngine {
    planner: Planner,
    policy_id: Option<PolicyId>,
}

pub(crate) struct PreparedQuery {
    query: QueryContext,
    key_identity: KeyIdentity,
    domain: Arc<str>,
    qtype: u16,
    plan: RequestPlan,
}

pub(crate) struct AnalyzedResponse {
    pub wire: Vec<u8>,
    pub class: ResponseClass,
    pub answer_ips: Vec<IpAddr>,
}

pub(crate) enum ResponseDirective {
    Accept {
        response: AnalyzedResponse,
        traversal: ResponseTraversal,
    },
    Reject {
        response: AnalyzedResponse,
        traversal: ResponseTraversal,
    },
    Requery {
        upstream: UpstreamTag,
        traversal: ResponseTraversal,
    },
}

impl DnsEngine {
    pub(crate) fn from_router(
        router: &DnsRouter,
        policy_id: Option<PolicyId>,
    ) -> Result<Self, EngineError> {
        let upstreams = router
            .upstream_names()
            .into_iter()
            .map(|name| UpstreamTag::new(&name))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            planner: Planner::new(router.clone(), upstreams),
            policy_id,
        })
    }

    pub(crate) fn prepare(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
        ingress: IngressProfile,
    ) -> Result<PreparedQuery, EngineError> {
        self.prepare_with_mode(raw_query, original_dst, ingress, false)
    }

    pub(crate) fn prepare_compatibility(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
        ingress: IngressProfile,
    ) -> Result<PreparedQuery, EngineError> {
        self.prepare_with_mode(raw_query, original_dst, ingress, true)
    }

    fn prepare_with_mode(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
        ingress: IngressProfile,
        compatibility: bool,
    ) -> Result<PreparedQuery, EngineError> {
        let query = QueryContext::parse_with_profile(raw_query, ingress)?;
        let domain: Arc<str> =
            decode_name(query.qname().ok_or(EngineError::MissingQuestion)?)?.into();
        let qtype = query.qtype().ok_or(EngineError::MissingQuestion)?.get();
        let context = RequestContext {
            domain: &domain,
            qtype,
            original_dst,
        };
        let plan = match self.planner.plan_request(context) {
            Err(PlanError::MissingOriginalDestination) if compatibility => {
                RequestPlan::Exchange(RequestScope::Upstream(UpstreamTag::new("default")?))
            }
            result => result?,
        };
        Ok(PreparedQuery {
            key_identity: KeyIdentity::new(&query, self.policy_id.clone()),
            query,
            domain,
            qtype,
            plan,
        })
    }

    pub(crate) fn analyze(
        &self,
        prepared: &PreparedQuery,
        traversal: ResponseTraversal,
        wire: Vec<u8>,
        strict: bool,
    ) -> Result<ResponseDirective, EngineError> {
        if strict {
            ResponseTemplate::validate(&prepared.query, &wire)?;
        }
        let class = classify_response(&wire);
        if matches!(class, ResponseClass::Nxdomain | ResponseClass::Servfail) {
            return Ok(ResponseDirective::Accept {
                response: AnalyzedResponse {
                    wire,
                    class,
                    answer_ips: Vec::new(),
                },
                traversal,
            });
        }
        let answer_ips = super::forwarder::extract_answer_ips(&wire);
        let current_traversal = traversal.clone();
        let planned = self.planner.plan_response(
            ResponseContext {
                domain: &prepared.domain,
                qtype: prepared.qtype,
                answer_ips: &answer_ips,
            },
            traversal,
        );
        let response = AnalyzedResponse {
            wire,
            class,
            answer_ips,
        };
        let plan = match planned {
            Err(PlanError::UpstreamCycle { .. } | PlanError::DepthExceeded { .. }) if !strict => {
                return Ok(ResponseDirective::Accept {
                    response,
                    traversal: current_traversal,
                });
            }
            result => result?,
        };
        Ok(match plan {
            ResponsePlan::Accept => ResponseDirective::Accept {
                response,
                traversal: current_traversal,
            },
            ResponsePlan::Reject => ResponseDirective::Reject {
                response,
                traversal: current_traversal,
            },
            ResponsePlan::Requery {
                upstream,
                traversal,
            } => ResponseDirective::Requery {
                upstream,
                traversal,
            },
        })
    }

    pub(crate) const fn policy_id(&self) -> Option<&PolicyId> {
        self.policy_id.as_ref()
    }
}

impl PreparedQuery {
    pub(crate) const fn query(&self) -> &QueryContext {
        &self.query
    }

    pub(crate) fn cache_key(
        &self,
        scope: RequestScope,
        operation: crate::dns::cache::OperationKind,
    ) -> crate::dns::cache::CacheKey {
        self.key_identity.key(scope, operation)
    }

    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn domain_arc(&self) -> Arc<str> {
        Arc::clone(&self.domain)
    }

    pub(crate) const fn qtype(&self) -> u16 {
        self.qtype
    }

    pub(crate) const fn plan(&self) -> &RequestPlan {
        &self.plan
    }

    pub(crate) const fn is_cacheable(&self) -> bool {
        self.query.is_cacheable()
    }

    pub(crate) const fn is_coalescable(&self) -> bool {
        self.query.is_coalescable()
    }
}

fn decode_name(name: &DnsName) -> Result<String, EngineError> {
    let mut labels = Vec::new();
    let mut cursor = 0;
    while let Some(&length) = name.as_wire().get(cursor) {
        if length == 0 {
            break;
        }
        cursor += 1;
        let end = cursor + usize::from(length);
        let label = name
            .as_wire()
            .get(cursor..end)
            .ok_or(EngineError::MalformedCanonicalName)?;
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| EngineError::MalformedCanonicalName)?
                .to_ascii_lowercase(),
        );
        cursor = end;
    }
    if labels.is_empty() {
        return Err(EngineError::MalformedCanonicalName);
    }
    Ok(labels.join("."))
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("DNS query parse failed: {0}")]
    Query(#[from] QueryError),
    #[error("DNS request has no question")]
    MissingQuestion,
    #[error("DNS canonical question name is malformed")]
    MalformedCanonicalName,
    #[error("DNS planning failed: {0}")]
    Plan(#[from] PlanError),
    #[error("DNS response validation failed: {0}")]
    Response(#[from] ResponseError),
}

#[cfg(test)]
mod tests;
