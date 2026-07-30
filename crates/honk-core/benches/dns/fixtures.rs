use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use honk_config::dns::{DnsRequestAction, DnsRequestRouting, DnsRouting};
use honk_core::dns::cache::DnsCache;
use honk_core::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use honk_core::dns::routing::DnsRouter;
use tokio::sync::Mutex;

pub(super) struct LoopbackPool {
    calls: AtomicU64,
    delayed: bool,
}

impl LoopbackPool {
    pub(super) const fn immediate() -> Self {
        Self {
            calls: AtomicU64::new(0),
            delayed: false,
        }
    }

    pub(super) const fn delayed() -> Self {
        Self {
            calls: AtomicU64::new(0),
            delayed: true,
        }
    }

    pub(super) fn reset_calls(&self) {
        self.calls.store(0, Ordering::Relaxed);
    }

    pub(super) fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl DnsUpstreamPool for LoopbackPool {
    async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let qtype = u16::from_be_bytes([
            raw_query[raw_query.len() - 4],
            raw_query[raw_query.len() - 3],
        ]);
        if self.delayed {
            let delay = if qtype == 1 { 50 } else { 100 };
            tokio::time::sleep(Duration::from_micros(delay)).await;
        } else {
            tokio::task::yield_now().await;
        }
        Ok(response(raw_query, qtype))
    }
}

pub(super) fn forwarder(pool: Arc<LoopbackPool>, cache_enabled: bool) -> Arc<DnsForwarder> {
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: Vec::new(),
                fallback: DnsRequestAction::Upstream("default".to_owned()),
            },
            ..Default::default()
        })
        .expect("benchmark router"),
    );
    Arc::new(
        DnsForwarder::new(pool, Arc::new(Mutex::new(DnsCache::new(10_000))), router)
            .with_cache_enabled(cache_enabled),
    )
}

fn response(query: &[u8], qtype: u16) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&qtype.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    match qtype {
        1 => response.extend_from_slice(&[0, 4, 127, 0, 0, 1]),
        28 => response.extend_from_slice(&[0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        _ => response.extend_from_slice(&[0, 0]),
    }
    response
}
