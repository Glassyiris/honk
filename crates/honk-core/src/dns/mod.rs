//! DNS resolver, forwarder, cache, and routing.
//!
//! ## Modules
//!
//! - `routing` — DNS request routing (domain → upstream)
//! - `cache` — DNS response cache with LRU and TTL
//! - `endpoint` — upstream address / SNI / path parsing
//! - `transport` — pooled UDP/TCP/DoT/DoH/DoQ/DoH3 clients
//! - `upstream_pool` — per-upstream DNS query management
//! - `forwarder` — DNS forwarding engine (cache + upstream + routing)
//! - `persist` — optional cache.db persistence for DNS answers
//! - `wire` — shared wire-format parsing helpers
//!
//! ## `DnsResolver`
//!
//! Application-level domain → IP helper used by the control plane (SNI
//! reality checks, etc.). Always resolves through a [`DnsForwarder`] so
//! the same upstream stack (including encrypted DNS and `outbound:`) is
//! shared with intercepted client queries. There is no separate stub
//! resolver dependency.

#[cfg(feature = "dns-bench")]
pub mod bench_support;
pub mod cache;
pub mod endpoint;
pub mod engine;
pub mod forwarder;
pub mod outcome;
pub mod persist;
pub mod planner;
pub mod policy;
pub(crate) mod projection;
pub mod query;
mod resolver;
pub mod response;
pub mod routing;
pub(crate) mod runtime;
mod service;
mod singleflight;
pub mod transport;
pub mod upstream_pool;
pub(crate) mod wire;

pub use resolver::{DnsResolver, ResolvedAddr};
pub use service::DnsService;
