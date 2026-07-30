//! Encrypted and pooled DNS transports (DoT / DoH / DoQ / DoH3).
//!
//! Design goals (performance-first):
//! - Never TLS/QUIC-handshake per query when a live session exists.
//! - DoT: small idle pool of TLS streams (sequential req/resp per stream).
//! - DoH: long-lived HTTP/2 session (`h2`) multiplexing concurrent queries.
//! - DoQ: one QUIC connection, one bi-stream per query (RFC 9250).
//! - DoH3: one QUIC+H3 session, POST `application/dns-message`.
//! - TCP plain: idle stream pool (same shape as DoT without TLS).
//!
//! All direct dials use `DAE_BYPASS_MARK` so eBPF does not re-intercept
//! control-plane DNS. Hostnames resolve via `honk_outbound::bootstrap`.

mod body;
mod dial;
mod doh;
mod doh3;
mod doh_message;
mod doq;
mod dot;
mod framing;
mod idle_pool;
mod lifecycle;
mod owned_task;
mod quic;
mod retry;
mod tcp_pool;

#[cfg(test)]
mod idle_pool_tests;
#[cfg(test)]
mod tests_proto;
#[cfg(test)]
mod upstream_lifecycle_tests;

use body::{DnsMessageBody, doh_content_length};
#[cfg(test)]
use body::{DnsMessageTooLarge, MAX_DNS_MESSAGE_SIZE};
use doh_message::{build_doh_request, finish_doh_response};
use idle_pool::{IdlePoolState, close_idle_pool, idle_pool_exchange};
use quic::{SharedQuicEndpoint, dns_quic_config, quic_connect};
use retry::exchange_with_retry;

pub use dial::{DialContext, ProxyDial};
pub use doh::DohClient;
pub use doh3::Doh3Client;
pub use doq::DoqClient;
pub use dot::DotPool;
pub use framing::{exchange_length_prefixed, force_dns_id_zero, restore_dns_id};
pub(crate) use lifecycle::LifecycleSlot;
pub use tcp_pool::TcpPool;
