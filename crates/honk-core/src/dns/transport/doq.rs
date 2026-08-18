//! DNS over QUIC (RFC 9250).
//!
//! One long-lived QUIC connection (ALPN `doq`); each query opens a
//! bidirectional stream, writes a length-prefixed message with ID=0,
//! finishes the send side, and reads the length-prefixed response.

use std::sync::Arc;
use std::time::Duration;

use crate::dns::endpoint::DnsEndpoint;
use quinn::{ClientConfig, Connection};

use super::framing::{
    force_dns_id_zero, read_length_prefixed, restore_dns_id, write_length_prefixed,
};
use super::lifecycle::LifecycleSlot;
use super::{SharedQuicEndpoint, dns_quic_config, exchange_with_retry, quic_connect_endpoint};

/// DoQ client for one upstream.
pub struct DoqClient {
    endpoint: DnsEndpoint,
    query_timeout: Duration,
    dial_timeout: Duration,
    quic_config: ClientConfig,
    quic_ep: SharedQuicEndpoint,
    connection: LifecycleSlot<Connection>,
}

impl DoqClient {
    pub async fn new(
        endpoint: DnsEndpoint,
        query_timeout: Duration,
        dial_timeout: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"doq"]).await?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            dial_timeout,
            quic_config,
            quic_ep: SharedQuicEndpoint::new(),
            connection: LifecycleSlot::new(),
        }))
    }

    pub async fn exchange(
        self: &Arc<Self>,
        raw_query: &[u8],
        feedback: Option<&honk_outbound::group::ScoreFeedback>,
    ) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoQ",
            raw_query,
            |reporter| async move { self.exchange_once(raw_query, reporter.as_ref()).await },
            || async { self.close_connection().await },
            feedback,
        )
        .await
    }

    async fn exchange_once(
        &self,
        raw_query: &[u8],
        reporter: Option<&honk_outbound::group::ScoreReporter>,
    ) -> anyhow::Result<Vec<u8>> {
        let conn = self.get_conn().await?;
        if let Some(reporter) = reporter {
            reporter.setup_succeeded();
        }
        tokio::time::timeout(self.query_timeout, async {
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| anyhow::anyhow!("DoQ open_bi: {e}"))?;

            let mut wire = raw_query.to_vec();
            let orig_id = force_dns_id_zero(&mut wire);
            write_length_prefixed(&mut send, &wire).await?;
            send.finish()
                .map_err(|e| anyhow::anyhow!("DoQ finish send: {e}"))?;
            if let Some(reporter) = reporter {
                reporter.tx(raw_query.len() as u64);
            }

            let mut resp = read_length_prefixed(&mut recv, self.query_timeout).await?;
            if let Some(reporter) = reporter
                && super::is_valid_response(raw_query, &resp)
            {
                reporter.first_response();
                reporter.rx(resp.len() as u64);
            }
            restore_dns_id(&mut resp, orig_id);
            Ok::<_, anyhow::Error>(resp)
        })
        .await
        .map_err(|_| anyhow::anyhow!("DoQ exchange timed out after {:?}", self.query_timeout))?
    }

    async fn get_conn(&self) -> anyhow::Result<Connection> {
        let connection = self.connection.acquire(|| self.dial()).await?;
        if connection.close_reason().is_some() {
            self.close_connection().await;
            return self
                .connection
                .acquire(|| self.dial())
                .await
                .map(|c| (*c).clone());
        }
        Ok((*connection).clone())
    }

    async fn dial(&self) -> anyhow::Result<Connection> {
        quic_connect_endpoint(
            &self.quic_ep,
            &self.quic_config,
            &self.endpoint,
            tokio::time::Instant::now() + self.dial_timeout,
            "DoQ",
        )
        .await
    }

    async fn close_connection(&self) {
        let timeout = self.query_timeout;
        self.connection
            .close(|connection| async move {
                connection.close(0_u32.into(), b"shutdown");
                let _ = tokio::time::timeout(timeout, connection.closed()).await;
            })
            .await;
    }

    pub(crate) async fn close(&self) {
        self.close_connection().await;
        self.quic_ep.close(self.query_timeout).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::types::DnsProtocol;

    #[tokio::test]
    async fn constructor_keeps_query_and_dial_timeouts_distinct() {
        let endpoint = DnsEndpoint::parse("127.0.0.1", DnsProtocol::Quic, Some("localhost"))
            .expect("DoQ endpoint");
        let client = DoqClient::new(
            endpoint,
            Duration::from_millis(111),
            Duration::from_millis(222),
        )
        .await
        .expect("DoQ client");

        assert_eq!(client.query_timeout, Duration::from_millis(111));
        assert_eq!(client.dial_timeout, Duration::from_millis(222));
    }
}
