//! Idle pool for plain DNS-over-TCP (RFC 7766).

use std::sync::Arc;

use parking_lot::Mutex;
use tracing::debug;

use super::DialContext;
use super::framing::exchange_length_prefixed;

const MAX_POOL_SIZE: usize = 4;

enum TcpStreamSlot {
    Direct(tokio::net::TcpStream),
    Boxed(Box<dyn crate::proxy::AsyncReadWrite>),
}

/// Idle-pool plain-TCP DNS client for one upstream.
pub struct TcpPool {
    dial: DialContext,
    idle: Mutex<Vec<TcpStreamSlot>>,
}

impl TcpPool {
    pub fn new(dial: DialContext) -> Arc<Self> {
        Arc::new(Self {
            dial,
            idle: Mutex::new(Vec::with_capacity(MAX_POOL_SIZE)),
        })
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.exchange_once(raw_query).await {
            Ok(r) => Ok(r),
            Err(first) => {
                debug!("TCP DNS exchange failed ({first}); redialing once");
                self.exchange_once(raw_query).await.map_err(|e| {
                    anyhow::anyhow!("TCP DNS failed after retry: {e} (first: {first})")
                })
            }
        }
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut slot = {
            let taken = self.idle.lock().pop();
            match taken {
                Some(s) => s,
                None => self.dial_new().await?,
            }
        };
        let result = match &mut slot {
            TcpStreamSlot::Direct(s) => {
                exchange_length_prefixed(s, raw_query, self.dial.query_timeout).await
            }
            TcpStreamSlot::Boxed(s) => {
                exchange_length_prefixed(s, raw_query, self.dial.query_timeout).await
            }
        };
        match result {
            Ok(resp) => {
                let mut idle = self.idle.lock();
                if idle.len() < MAX_POOL_SIZE {
                    idle.push(slot);
                }
                Ok(resp)
            }
            Err(e) => Err(e),
        }
    }

    async fn dial_new(&self) -> anyhow::Result<TcpStreamSlot> {
        if self.dial.proxy.is_some() {
            Ok(TcpStreamSlot::Boxed(self.dial.dial_tcp_boxed().await?))
        } else {
            Ok(TcpStreamSlot::Direct(self.dial.dial_tcp().await?))
        }
    }
}
