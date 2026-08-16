use super::{DnsEngine, EngineError, classify_response, effective_expiry};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use honk_config::dns::{
    DnsCond, DnsConfig, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
    DnsResponseRule, DnsRouting,
};
use tokio::sync::{Barrier, Mutex, mpsc};

use crate::dns::cache::{CacheKey, DnsCache, OperationKind};
use crate::dns::forwarder::{DnsForwardError, DnsForwarder, DnsUpstreamPool, build_dns_query};
use crate::dns::outcome::{OutcomeStatus, Provenance, ResponseClass};
use crate::dns::planner::{PlanError, RequestPlan};
use crate::dns::query::{DnsRequestMeta, IngressProfile};
use crate::dns::routing::DnsRouter;
