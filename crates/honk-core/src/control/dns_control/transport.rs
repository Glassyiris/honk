use super::DnsController;
use crate::dns::query::{
    DnsRequestMeta, IngressProfile, ValidatedDnsQuery, is_exact_dns_query, validate_exact_dns_query,
};
use crate::dns::response::build_dns_refused;
use crate::dns::transport::{read_length_prefixed_into, write_length_prefixed};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

pub(super) const TCP_DNS_IO_TIMEOUT: Duration = Duration::from_secs(30);

impl DnsController {
    /// Handle a UDP DNS query from TPROXY.
    pub(crate) async fn handle_udp_dns(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        validated: Option<ValidatedDnsQuery>,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 {
            return Ok(false);
        }
        let Some(validated) = validated.or_else(|| validate_exact_dns_query(data)) else {
            return Ok(false);
        };
        // Keep the permit through the reply write so the limit bounds the
        // complete request lifecycle rather than only upstream resolution.
        let _permit = match self.try_acquire_query() {
            Ok(permit) => permit,
            Err(_) => {
                debug!("DNS concurrency limit reached; sending REFUSED");
                let response = build_dns_refused(data);
                let _ = super::super::send_udp_reply_from_orig_dst(
                    &response,
                    client_addr,
                    original_dst,
                )
                .await;
                return Ok(true);
            }
        };

        debug!(%client_addr, "DNS controller (UDP): forwarding query");
        let response = self
            .answer_query(
                data,
                DnsRequestMeta::new(Some(client_addr.ip()), Some(original_dst)),
                validated.ingress(),
            )
            .await;
        let _ =
            super::super::send_udp_reply_from_orig_dst(&response, client_addr, original_dst).await;
        Ok(true)
    }

    /// Handle a TCP DNS-over-TCP connection from TPROXY.
    pub async fn handle_tcp_dns(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 {
            return Ok(false);
        }
        self.serve_tcp_frames(stream, client_addr, Some(original_dst))
            .await
    }

    /// Serve a standalone DNS-over-TCP connection in the host namespace.
    pub(crate) async fn serve_bound_tcp_dns(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let _ = self.serve_tcp_frames(stream, client_addr, None).await?;
        Ok(())
    }

    /// Sequential RFC 7766 request loop shared by transparent and bound TCP.
    /// Port 53 belongs to DNS once intercepted; malformed, idle, or partial
    /// frames close the connection rather than falling through after consuming bytes.
    async fn serve_tcp_frames(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        original_dst: Option<SocketAddr>,
    ) -> anyhow::Result<bool> {
        stream.set_nodelay(true)?;
        let metadata = DnsRequestMeta::new(Some(client_addr.ip()), original_dst);
        let mut query = Vec::new();
        if !read_tcp_dns_query(stream, &mut query, Some(TCP_DNS_IO_TIMEOUT)).await {
            return Ok(original_dst.is_some());
        }

        debug!(%client_addr, "DNS controller (TCP): forwarding query");
        self.process_tcp_query(stream, &query, metadata).await?;

        loop {
            if !read_tcp_dns_query(stream, &mut query, Some(TCP_DNS_IO_TIMEOUT)).await {
                return Ok(true);
            }
            self.process_tcp_query(stream, &query, metadata).await?;
        }
    }

    async fn process_tcp_query(
        &self,
        stream: &mut TcpStream,
        query: &[u8],
        metadata: DnsRequestMeta,
    ) -> anyhow::Result<()> {
        // Keep the permit through the framed response write, including every
        // frame on a persistent TCP connection.
        match self.try_acquire_query() {
            Ok(_permit) => {
                let response = self
                    .answer_query(query, metadata, IngressProfile::Tcp)
                    .await;
                write_tcp_dns_response(stream, &response, TCP_DNS_IO_TIMEOUT).await
            }
            Err(_) => {
                write_tcp_dns_response(stream, &build_dns_refused(query), TCP_DNS_IO_TIMEOUT).await
            }
        }
    }
}

async fn write_tcp_dns_response(
    stream: &mut TcpStream,
    response: &[u8],
    timeout: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, write_length_prefixed(stream, response))
        .await
        .map_err(|_| anyhow::anyhow!("DNS TCP response write timed out"))?
}

async fn read_tcp_dns_query(
    stream: &mut TcpStream,
    query: &mut Vec<u8>,
    read_timeout: Option<Duration>,
) -> bool {
    read_length_prefixed_into(stream, query, read_timeout)
        .await
        .is_ok()
        && is_exact_dns_query(query)
}
